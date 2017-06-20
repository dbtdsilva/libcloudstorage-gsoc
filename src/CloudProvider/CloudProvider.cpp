/*****************************************************************************
 * CloudProvider.cpp : implementation of CloudProvider
 *
 *****************************************************************************
 * Copyright (C) 2016-2016 VideoLAN
 *
 * Authors: Paweł Wegner <pawel.wegner95@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#include "CloudProvider.h"

#include <json/json.h>
#include <cstring>
#include <fstream>
#include <sstream>

#include "Utility/Item.h"
#include "Utility/Utility.h"

#include "Request/CreateDirectoryRequest.h"
#include "Request/DeleteItemRequest.h"
#include "Request/DownloadFileRequest.h"
#include "Request/GetItemDataRequest.h"
#include "Request/GetItemRequest.h"
#include "Request/ListDirectoryRequest.h"
#include "Request/MoveItemRequest.h"
#include "Request/RenameItemRequest.h"
#include "Request/UploadFileRequest.h"

#ifdef WITH_CRYPTOPP
#include "Utility/CryptoPP.h"
#endif

#ifdef WITH_CURL
#include "Utility/CurlHttp.h"
#endif

#ifdef WITH_THUMBNAILER
#include "Utility/FFmpegThumbnailer.h"
#endif

#ifdef WITH_MICROHTTPD
#include "Utility/MicroHttpd.h"
#endif

using namespace std::placeholders;

namespace {

class ListDirectoryCallback : public cloudstorage::IListDirectoryCallback {
 public:
  ListDirectoryCallback(cloudstorage::ListDirectoryCallback callback)
      : callback_(callback) {}

  void receivedItem(cloudstorage::IItem::Pointer) override {}

  void done(const std::vector<cloudstorage::IItem::Pointer>& result) override {
    callback_(result);
  }

  void error(const std::string&) override { callback_({}); }

 private:
  cloudstorage::ListDirectoryCallback callback_;
};

class DownloadFileCallback : public cloudstorage::IDownloadFileCallback {
 public:
  DownloadFileCallback(const std::string& filename,
                       cloudstorage::DownloadFileCallback callback)
      : file_(filename, std::ios_base::out | std::ios_base::binary),
        callback_(callback) {}

  void receivedData(const char* data, uint32_t length) override {
    file_.write(data, length);
  }

  void done() override {
    file_.close();
    callback_(true);
  }

  void error(const std::string&) override {
    file_.close();
    callback_(false);
  }

  void progress(uint32_t, uint32_t) override {}

 private:
  std::fstream file_;
  cloudstorage::DownloadFileCallback callback_;
};

class UploadFileCallback : public cloudstorage::IUploadFileCallback {
 public:
  UploadFileCallback(const std::string& path,
                     cloudstorage::UploadFileCallback callback)
      : file_(path, std::ios_base::in | std::ios_base::binary),
        callback_(callback) {
    file_.seekg(0, std::ios::end);
    size_ = file_.tellg();
    file_.seekg(std::ios::beg);
  }

  void reset() override {
    file_.clear();
    file_.seekg(std::ios::beg);
  }

  uint32_t putData(char* data, uint32_t maxlength) override {
    file_.read(data, maxlength);
    return file_.gcount();
  }

  uint64_t size() override { return size_; }

  void done() override { callback_(true); }

  void error(const std::string&) override { callback_(false); }

  void progress(uint32_t, uint32_t) override {}

 private:
  std::fstream file_;
  cloudstorage::UploadFileCallback callback_;
  uint64_t size_;
};

}  // namespace

namespace cloudstorage {

CloudProvider::CloudProvider(IAuth::Pointer auth)
    : auth_(std::move(auth)),
      http_(), httpd_(),
      current_authorization_status_(AuthorizationStatus::None) {}

void CloudProvider::initialize(InitData&& data) {
  std::lock_guard<std::mutex> lock(auth_mutex_);
  callback_ = std::move(data.callback_);
  crypto_ = std::move(data.crypto_engine_);
  http_ = std::move(data.http_engine_);
  httpd_ = std::move(data.httpd_engine_);
  thumbnailer_ = std::move(data.thumbnailer_);

  auto t = auth()->fromTokenString(data.token_);
  setWithHint(data.hints_, "access_token",
              [&t](std::string v) { t->token_ = v; });
  auth()->set_access_token(std::move(t));

  setWithHint(data.hints_, "client_id",
              [this](std::string v) { auth()->set_client_id(v); });
  setWithHint(data.hints_, "client_secret",
              [this](std::string v) { auth()->set_client_secret(v); });
  setWithHint(data.hints_, "redirect_uri_port", [this](std::string v) {
                  auth()->set_redirect_uri_port(std::atoi(v.c_str())); });
  setWithHint(data.hints_, "redirect_uri_prefix", [this](std::string v) {
                  auth()->set_redirect_uri_prefix(v); });
  setWithHint(data.hints_, "requesting_app_name", [this](std::string v) {
                  auth()->set_requesting_app_name(v); });

#ifdef WITH_CRYPTOPP
  if (!crypto_) crypto_ = util::make_unique<CryptoPP>();
#endif

#ifdef WITH_CURL
  if (!http_) http_ = util::make_unique<CurlHttp>();
#endif

#ifdef WITH_THUMBNAILER
  if (!thumbnailer_) thumbnailer_ = util::make_unique<FFmpegThumbnailer>();
#endif
  
#ifdef WITH_MICROHTTPD
  if (!httpd_) httpd_ = util::make_unique<MicroHttpd>();
#endif

  if (!http_) throw std::runtime_error("No http module specified.");
  if (!httpd_) throw std::runtime_error("No httpd module specified.");
  auth()->initialize(http(), httpd());
}

ICloudProvider::Hints CloudProvider::hints() const {
  return {{"access_token", access_token()}};
}

std::string CloudProvider::access_token() const {
  std::lock_guard<std::mutex> lock(auth_mutex_);
  if (auth()->access_token() == nullptr) return "";
  return auth()->access_token()->token_;
}

IAuth* CloudProvider::auth() const { return auth_.get(); }

std::string CloudProvider::authorizeLibraryUrl() const {
  return auth()->authorizeLibraryUrl();
}

std::string CloudProvider::token() const {
  std::lock_guard<std::mutex> lock(auth_mutex_);
  if (auth()->access_token() == nullptr) return "";
  return auth()->access_token()->refresh_token_;
}

IItem::Pointer CloudProvider::rootDirectory() const {
  return util::make_unique<Item>("/", "root", IItem::FileType::Directory);
}

ICloudProvider::ICallback* CloudProvider::callback() const {
  return callback_.get();
}

ICrypto* CloudProvider::crypto() const { return crypto_.get(); }

IHttp* CloudProvider::http() const { return http_.get(); }

IHttpd* CloudProvider::httpd() const { return httpd_.get(); }

IThumbnailer* CloudProvider::thumbnailer() const { return thumbnailer_.get(); }

ICloudProvider::ListDirectoryRequest::Pointer CloudProvider::listDirectoryAsync(
    IItem::Pointer item, IListDirectoryCallback::Pointer callback) {
  return util::make_unique<cloudstorage::ListDirectoryRequest>(
      shared_from_this(), std::move(item), std::move(callback));
}

ICloudProvider::GetItemRequest::Pointer CloudProvider::getItemAsync(
    const std::string& absolute_path, GetItemCallback callback) {
  return util::make_unique<cloudstorage::GetItemRequest>(
      shared_from_this(), absolute_path, callback);
}

ICloudProvider::DownloadFileRequest::Pointer CloudProvider::downloadFileAsync(
    IItem::Pointer file, IDownloadFileCallback::Pointer callback) {
  return util::make_unique<cloudstorage::DownloadFileRequest>(
      shared_from_this(), std::move(file), std::move(callback),
      std::bind(&CloudProvider::downloadFileRequest, this, _1, _2));
}

ICloudProvider::UploadFileRequest::Pointer CloudProvider::uploadFileAsync(
    IItem::Pointer directory, const std::string& filename,
    IUploadFileCallback::Pointer callback) {
  return util::make_unique<cloudstorage::UploadFileRequest>(
      shared_from_this(), std::move(directory), filename, std::move(callback));
}

ICloudProvider::GetItemDataRequest::Pointer CloudProvider::getItemDataAsync(
    const std::string& id, GetItemDataCallback f) {
  return util::make_unique<cloudstorage::GetItemDataRequest>(shared_from_this(),
                                                             id, f);
}

void CloudProvider::authorizeRequest(IHttpRequest& r) const {
  r.setHeaderParameter("Authorization", "Bearer " + access_token());
}

bool CloudProvider::reauthorize(int code) const {
  return IHttpRequest::isAuthorizationError(code);
}

AuthorizeRequest::Pointer CloudProvider::authorizeAsync() {
  return util::make_unique<AuthorizeRequest>(shared_from_this());
}

std::mutex& CloudProvider::auth_mutex() const { return auth_mutex_; }

std::mutex& CloudProvider::current_authorization_mutex() const {
  return current_authorization_mutex_;
}

std::condition_variable& CloudProvider::authorized_condition() const {
  return authorized_;
}

CloudProvider::AuthorizationStatus CloudProvider::authorization_status() const {
  std::unique_lock<std::mutex> lock(authorization_status_mutex_);
  return current_authorization_status_;
}

void CloudProvider::set_authorization_status(
    CloudProvider::AuthorizationStatus status) {
  std::unique_lock<std::mutex> lock(authorization_status_mutex_);
  current_authorization_status_ = status;
}

AuthorizeRequest::Pointer CloudProvider::current_authorization() const {
  return current_authorization_;
}

void CloudProvider::set_current_authorization(AuthorizeRequest::Pointer r) {
  current_authorization_ = r;
}

void CloudProvider::setWithHint(const ICloudProvider::Hints& hints,
                                const std::string& name,
                                std::function<void(std::string)> f) const {
  auto it = hints.find(name);
  if (it != hints.end()) f(it->second);
}

std::string CloudProvider::getPath(const std::string& p) {
  std::string result = p;
  if (result.back() == '/') result.pop_back();
  return result.substr(0, result.find_last_of('/'));
}

std::string CloudProvider::getFilename(const std::string& path) {
  std::string result = path;
  if (result.back() == '/') result.pop_back();
  return result.substr(result.find_last_of('/') + 1);
}

std::pair<std::string, std::string> CloudProvider::creditentialsFromString(
    const std::string& str) {
  auto it = str.find(Auth::SEPARATOR);
  if (it == std::string::npos) return {};
  std::string login(str.begin(), str.begin() + it);
  std::string password(str.begin() + it + strlen(Auth::SEPARATOR), str.end());
  return {login, password};
}

ICloudProvider::DownloadFileRequest::Pointer CloudProvider::getThumbnailAsync(
    IItem::Pointer item, IDownloadFileCallback::Pointer callback) {
  return util::make_unique<cloudstorage::DownloadFileRequest>(
      shared_from_this(), item, std::move(callback),
      std::bind(&CloudProvider::getThumbnailRequest, this, _1, _2), true);
}

ICloudProvider::DeleteItemRequest::Pointer CloudProvider::deleteItemAsync(
    IItem::Pointer item, DeleteItemCallback callback) {
  return util::make_unique<cloudstorage::DeleteItemRequest>(shared_from_this(),
                                                            item, callback);
}

ICloudProvider::CreateDirectoryRequest::Pointer
CloudProvider::createDirectoryAsync(IItem::Pointer parent,
                                    const std::string& name,
                                    CreateDirectoryCallback callback) {
  return util::make_unique<cloudstorage::CreateDirectoryRequest>(
      shared_from_this(), parent, name, callback);
}

ICloudProvider::MoveItemRequest::Pointer CloudProvider::moveItemAsync(
    IItem::Pointer source, IItem::Pointer destination,
    MoveItemCallback callback) {
  return util::make_unique<cloudstorage::MoveItemRequest>(
      shared_from_this(), source, destination, callback);
}

ICloudProvider::RenameItemRequest::Pointer CloudProvider::renameItemAsync(
    IItem::Pointer item, const std::string& name, RenameItemCallback callback) {
  return util::make_unique<cloudstorage::RenameItemRequest>(
      shared_from_this(), item, name, callback);
}

ICloudProvider::ListDirectoryRequest::Pointer CloudProvider::listDirectoryAsync(
    IItem::Pointer item, ListDirectoryCallback callback) {
  return listDirectoryAsync(
      item, util::make_unique<::ListDirectoryCallback>(callback));
}

ICloudProvider::DownloadFileRequest::Pointer CloudProvider::downloadFileAsync(
    IItem::Pointer item, const std::string& filename,
    DownloadFileCallback callback) {
  return downloadFileAsync(
      item, util::make_unique<::DownloadFileCallback>(filename, callback));
}

ICloudProvider::DownloadFileRequest::Pointer CloudProvider::getThumbnailAsync(
    IItem::Pointer item, const std::string& filename,
    GetThumbnailCallback callback) {
  return getThumbnailAsync(
      item, util::make_unique<::DownloadFileCallback>(filename, callback));
}

ICloudProvider::UploadFileRequest::Pointer CloudProvider::uploadFileAsync(
    IItem::Pointer parent, const std::string& path, const std::string& filename,
    UploadFileCallback callback) {
  return uploadFileAsync(
      parent, filename,
      util::make_unique<::UploadFileCallback>(path, callback));
}

IHttpRequest::Pointer CloudProvider::getItemDataRequest(const std::string&,
                                                        std::ostream&) const {
  return nullptr;
}

IHttpRequest::Pointer CloudProvider::listDirectoryRequest(const IItem&,
                                                          const std::string&,
                                                          std::ostream&) const {
  return nullptr;
}

IHttpRequest::Pointer CloudProvider::uploadFileRequest(const IItem&,
                                                       const std::string&,
                                                       std::ostream&,
                                                       std::ostream&) const {
  return nullptr;
}

IHttpRequest::Pointer CloudProvider::downloadFileRequest(const IItem&,
                                                         std::ostream&) const {
  return nullptr;
}

IHttpRequest::Pointer CloudProvider::getThumbnailRequest(const IItem& i,
                                                         std::ostream&) const {
  const Item& item = static_cast<const Item&>(i);
  if (item.thumbnail_url().empty()) return nullptr;
  return http()->create(item.thumbnail_url(), "GET");
}

IHttpRequest::Pointer CloudProvider::deleteItemRequest(const IItem&,
                                                       std::ostream&) const {
  return nullptr;
}

IHttpRequest::Pointer CloudProvider::createDirectoryRequest(
    const IItem&, const std::string&, std::ostream&) const {
  return nullptr;
}

IHttpRequest::Pointer CloudProvider::moveItemRequest(const IItem&, const IItem&,
                                                     std::ostream&) const {
  return nullptr;
}

IHttpRequest::Pointer CloudProvider::renameItemRequest(const IItem&,
                                                       const std::string&,
                                                       std::ostream&) const {
  return nullptr;
}

IItem::Pointer CloudProvider::getItemDataResponse(std::istream&) const {
  return nullptr;
}

std::vector<IItem::Pointer> CloudProvider::listDirectoryResponse(
    std::istream&, std::string&) const {
  return {};
}

IItem::Pointer CloudProvider::createDirectoryResponse(
    std::istream& stream) const {
  return getItemDataResponse(stream);
}

}  // namespace cloudstorage
