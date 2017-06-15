/*****************************************************************************
 * YandexDisk.cpp : YandexDisk implementation
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

#include "YandexDisk.h"

#include <json/json.h>

#include "Request/DownloadFileRequest.h"
#include "Request/Request.h"
#include "Request/UploadFileRequest.h"
#include "Utility/Item.h"
#include "Utility/Utility.h"

using namespace std::placeholders;

namespace cloudstorage {

YandexDisk::YandexDisk() : CloudProvider(util::make_unique<Auth>()) {}

std::string YandexDisk::name() const { return "yandex"; }

std::string YandexDisk::endpoint() const {
  return "https://cloud-api.yandex.net";
}

IItem::Pointer YandexDisk::rootDirectory() const {
  return util::make_unique<Item>("disk", "disk:/", IItem::FileType::Directory);
}

ICloudProvider::GetItemDataRequest::Pointer YandexDisk::getItemDataAsync(
    const std::string& id, GetItemDataCallback callback) {
  auto r = util::make_unique<Request<IItem::Pointer>>(shared_from_this());
  r->set_resolver(
      [this, id, callback](Request<IItem::Pointer>* r) -> IItem::Pointer {
        std::stringstream output;
        int code = r->sendRequest(
            [this, id](std::ostream&) {
              auto request =
                  http()->create(endpoint() + "/v1/disk/resources", "GET");
              request->setParameter("path", id);
              return request;
            },
            output);
        if (!IHttpRequest::isSuccess(code)) {
          callback(nullptr);
          return nullptr;
        }
        Json::Value json;
        output >> json;
        auto item = toItem(json);
        if (item->type() != IItem::FileType::Directory) {
          code = r->sendRequest(
              [this, id](std::ostream&) {
                auto request = http()->create(
                    endpoint() + "/v1/disk/resources/download", "GET");
                request->setParameter("path", id);
                return request;
              },
              output);
          if (IHttpRequest::isSuccess(code)) {
            output >> json;
            static_cast<Item*>(item.get())->set_url(json["href"].asString());
          }
        }
        callback(item);
        return item;
      });
  return std::move(r);
}

ICloudProvider::DownloadFileRequest::Pointer YandexDisk::downloadFileAsync(
    IItem::Pointer item, IDownloadFileCallback::Pointer callback) {
  auto r = util::make_unique<Request<void>>(shared_from_this());
  r->set_error_callback(
      [this, callback](Request<void>* r, int code, const std::string& desc) {
        callback->error(r->error_string(code, desc));
      });
  r->set_resolver([this, item, callback](Request<void>* r) -> void {
    std::stringstream output;
    int code = r->sendRequest(
        [this, item](std::ostream&) {
          auto request =
              http()->create(endpoint() + "/v1/disk/resources/download", "GET");
          request->setParameter("path", item->id());
          return request;
        },
        output);
    if (!IHttpRequest::isSuccess(code))
      callback->error("Couldn't get download url.");
    else {
      Json::Value json;
      output >> json;
      DownloadStreamWrapper wrapper(std::bind(
          &IDownloadFileCallback::receivedData, callback.get(), _1, _2));
      std::ostream stream(&wrapper);
      std::string url = json["href"].asString();
      code = r->sendRequest(
          [this, url](std::ostream&) { return http()->create(url, "GET"); },
          stream,
          std::bind(&IDownloadFileCallback::progress, callback.get(), _1, _2));
      if (IHttpRequest::isSuccess(code)) callback->done();
    }
  });
  return std::move(r);
}

ICloudProvider::UploadFileRequest::Pointer YandexDisk::uploadFileAsync(
    IItem::Pointer directory, const std::string& filename,
    IUploadFileCallback::Pointer callback) {
  auto r = util::make_unique<Request<void>>(shared_from_this());
  r->set_error_callback(
      [callback](Request<void>* r, int code, const std::string& desc) {
        callback->error(r->error_string(code, desc));
      });
  r->set_resolver([this, directory, filename, callback](Request<void>* r) {
    std::stringstream output;
    int code = r->sendRequest(
        [this, directory, filename](std::ostream&) {
          auto request =
              http()->create(endpoint() + "/v1/disk/resources/upload", "GET");
          std::string path = directory->id();
          if (path.back() != '/') path += "/";
          path += filename;
          request->setParameter("path", path);
          return request;
        },
        output);
    if (IHttpRequest::isSuccess(code)) {
      Json::Value response;
      output >> response;
      std::string url = response["href"].asString();
      UploadStreamWrapper wrapper(
          std::bind(&IUploadFileCallback::putData, callback.get(), _1, _2),
          callback->size());
      code = r->sendRequest(
          [this, url, callback, &wrapper](std::ostream& input) {
            auto request = http()->create(url, "PUT");
            callback->reset();
            wrapper.reset();
            input.rdbuf(&wrapper);
            return request;
          },
          output, nullptr,
          std::bind(&IUploadFileCallback::progress, callback.get(), _1, _2));
      if (IHttpRequest::isSuccess(code)) callback->done();
    } else
      callback->error("Couldn't get upload url.");
  });
  return std::move(r);
}

ICloudProvider::CreateDirectoryRequest::Pointer
YandexDisk::createDirectoryAsync(IItem::Pointer parent, const std::string& name,
                                 CreateDirectoryCallback callback) {
  auto r = util::make_unique<Request<IItem::Pointer>>(shared_from_this());
  r->set_resolver([=](Request<IItem::Pointer>* r) -> IItem::Pointer {
    std::stringstream output;
    int code = r->sendRequest(
        [=](std::ostream&) {
          auto request =
              http()->create(endpoint() + "/v1/disk/resources/", "PUT");
          request->setParameter(
              "path",
              parent->id() + (parent->id().back() == '/' ? "" : "/") + name);
          return request;
        },
        output);
    if (IHttpRequest::isSuccess(code)) {
      Json::Value json;
      output >> json;
      code = r->sendRequest(
          [=](std::ostream&) {
            auto request = http()->create(json["href"].asString(), "GET");
            return request;
          },
          output);
      if (IHttpRequest::isSuccess(code)) {
        output >> json;
        auto item = toItem(json);
        callback(item);
        return item;
      }
    }
    callback(nullptr);
    return nullptr;
  });
  return std::move(r);
}

IHttpRequest::Pointer YandexDisk::listDirectoryRequest(
    const IItem& item, const std::string& page_token, std::ostream&) const {
  auto request = http()->create(endpoint() + "/v1/disk/resources", "GET");
  request->setParameter("path", item.id());
  if (!page_token.empty()) request->setParameter("offset", page_token);
  return request;
}

IHttpRequest::Pointer YandexDisk::deleteItemRequest(const IItem& item,
                                                    std::ostream&) const {
  auto request = http()->create(endpoint() + "/v1/disk/resources", "DELETE");
  request->setParameter("path", item.id());
  request->setParameter("permamently", "true");
  return request;
}

IHttpRequest::Pointer YandexDisk::moveItemRequest(const IItem& source,
                                                  const IItem& destination,
                                                  std::ostream&) const {
  auto request = http()->create(endpoint() + "/v1/disk/resources/move", "POST");
  request->setParameter("from", source.id());
  request->setParameter(
      "path", destination.id() + (destination.id().back() == '/' ? "" : "/") +
                  source.filename());
  return request;
}

IHttpRequest::Pointer YandexDisk::renameItemRequest(const IItem& item,
                                                    const std::string& name,
                                                    std::ostream&) const {
  auto request = http()->create(endpoint() + "/v1/disk/resources/move", "POST");
  request->setParameter("from", item.id());
  request->setParameter("path", getPath(item.id()) + "/" + name);
  return request;
}

std::vector<IItem::Pointer> YandexDisk::listDirectoryResponse(
    std::istream& stream, std::string& next_page_token) const {
  Json::Value response;
  stream >> response;
  std::vector<IItem::Pointer> result;
  for (const Json::Value& v : response["_embedded"]["items"])
    result.push_back(toItem(v));
  int offset = response["_embedded"]["offset"].asInt();
  int limit = response["_embedded"]["limit"].asInt();
  int total_count = response["_embedded"]["total"].asInt();
  if (offset + limit < total_count)
    next_page_token = std::to_string(offset + limit);
  return result;
}

IItem::Pointer YandexDisk::toItem(const Json::Value& v) const {
  IItem::FileType type = v["type"].asString() == "dir"
                             ? IItem::FileType::Directory
                             : Item::fromMimeType(v["mime_type"].asString());
  auto item =
      util::make_unique<Item>(v["name"].asString(), v["path"].asString(), type);
  item->set_thumbnail_url(v["preview"].asString());
  return std::move(item);
}

void YandexDisk::authorizeRequest(IHttpRequest& request) const {
  request.setHeaderParameter("Authorization", "OAuth " + access_token());
}

YandexDisk::Auth::Auth() {
  set_client_id("e2a57a217113406999d521fc2234dbcb");
  set_client_secret("7090e0844c634e9baff3735fd6e199de");
}

std::string YandexDisk::Auth::authorizeLibraryUrl() const {
  return "https://oauth.yandex.com/authorize?response_type=code&client_id=" +
         client_id();
}

IHttpRequest::Pointer YandexDisk::Auth::exchangeAuthorizationCodeRequest(
    std::ostream& input_data) const {
  auto request = http()->create("https://oauth.yandex.com/token", "POST");
  input_data << "grant_type=authorization_code&"
             << "client_id=" << client_id() << "&"
             << "client_secret=" << client_secret() << "&"
             << "code=" << authorization_code();
  return request;
}

IHttpRequest::Pointer YandexDisk::Auth::refreshTokenRequest(
    std::ostream&) const {
  return nullptr;
}

IAuth::Token::Pointer YandexDisk::Auth::exchangeAuthorizationCodeResponse(
    std::istream& stream) const {
  Json::Value response;
  stream >> response;
  auto token = util::make_unique<Token>();
  token->expires_in_ = -1;
  token->token_ = response["access_token"].asString();
  token->refresh_token_ = token->token_;
  return token;
}

IAuth::Token::Pointer YandexDisk::Auth::refreshTokenResponse(
    std::istream&) const {
  return nullptr;
}

}  // namespace cloudstorage
