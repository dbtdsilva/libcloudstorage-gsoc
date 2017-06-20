/*****************************************************************************
 * MegaNz.cpp : Mega implementation
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

#include "MegaNz.h"

#include "IAuth.h"
#include "Request/DownloadFileRequest.h"
#include "Request/Request.h"
#include "Utility/Item.h"
#include "Utility/Utility.h"

#include <array>
#include <cstring>
#include <fstream>
#include <queue>

using namespace mega;

const int BUFFER_SIZE = 1024;
const int CACHE_FILENAME_LENGTH = 12;
const int DEFAULT_DAEMON_PORT = 12346;

namespace cloudstorage {

namespace {

class Listener {
 public:
  static constexpr int IN_PROGRESS = -1;
  static constexpr int FAILURE = 0;
  static constexpr int SUCCESS = 1;

  Listener(Semaphore* semaphore)
      : semaphore_(semaphore), status_(IN_PROGRESS) {}

  Semaphore* semaphore_;
  std::atomic_int status_;
};

class RequestListener : public mega::MegaRequestListener, public Listener {
 public:
  using Listener::Listener;

  void onRequestFinish(MegaApi*, MegaRequest* r, MegaError* e) override {
    if (e->getErrorCode() == 0)
      status_ = SUCCESS;
    else
      status_ = FAILURE;
    if (r->getLink()) link_ = r->getLink();
    node_ = r->getNodeHandle();
    semaphore_->notify();
  }

  std::string link_;
  MegaHandle node_;
};

class TransferListener : public mega::MegaTransferListener, public Listener {
 public:
  using Listener::Listener;

  bool onTransferData(MegaApi*, MegaTransfer* t, char* buffer,
                      size_t size) override {
    if (download_callback_) {
      download_callback_->receivedData(buffer, size);
      download_callback_->progress(t->getTotalBytes(),
                                   t->getTransferredBytes());
    }
    return !request_->is_cancelled();
  }

  void onTransferUpdate(MegaApi* mega, MegaTransfer* t) override {
    if (upload_callback_)
      upload_callback_->progress(t->getTotalBytes(), t->getTransferredBytes());
    if (request_->is_cancelled()) mega->cancelTransfer(t);
  }

  void onTransferFinish(MegaApi*, MegaTransfer*, MegaError* e) override {
    if (e->getErrorCode() == 0)
      status_ = SUCCESS;
    else {
      error_ = e->getErrorString();
      status_ = FAILURE;
    }
    semaphore_->notify();
  }

  IDownloadFileCallback::Pointer download_callback_;
  IUploadFileCallback::Pointer upload_callback_;
  Request<void>* request_;
  std::string error_;
};

struct HttpData {
  HttpData() {}

  std::mutex mutex_;
  std::queue<char> buffer_;
  ICloudProvider::DownloadFileRequest::Pointer request_;
};

class DownloadFileCallback : public IDownloadFileCallback {
 public:
  DownloadFileCallback(HttpData* data) : data_(data) {}

  void receivedData(const char* data, uint32_t length) override {
    std::lock_guard<std::mutex> lock(data_->mutex_);
    for (uint32_t i = 0; i < length; i++) data_->buffer_.push(data[i]);
  }

  void done() override {}
  void error(const std::string&) override {}
  void progress(uint32_t, uint32_t) override {}

  HttpData* data_;
};

int httpRequestCallback(void* cls, MHD_Connection* connection, const char*,
                        const char* /*method*/, const char* /*version*/,
                        const char* /*upload_data*/,
                        size_t* /*upload_data_size*/, void** /*ptr*/) {
  MegaNz* provider = static_cast<MegaNz*>(cls);
  const char* file =
      MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "file");
  std::unique_ptr<mega::MegaNode> node(provider->mega()->getNodeByHandle(
      provider->mega()->base64ToHandle(file)));
  if (!node) return MHD_NO;
  auto data_provider = [](void* cls, uint64_t, char* buf,
                          size_t max) -> ssize_t {
    HttpData* data = static_cast<HttpData*>(cls);
    std::lock_guard<std::mutex> lock(data->mutex_);
    size_t cnt = std::min(data->buffer_.size(), max);
    for (size_t i = 0; i < cnt; i++) {
      buf[i] = data->buffer_.front();
      data->buffer_.pop();
    }
    return cnt;
  };
  auto release_data = [](void* cls) {
    HttpData* data = static_cast<HttpData*>(cls);
    delete data;
  };
  HttpData* data = new HttpData;
  auto request = util::make_unique<Request<void>>(
      std::weak_ptr<CloudProvider>(provider->shared_from_this()));
  request->set_resolver(provider->downloadResolver(
      provider->toItem(node.get()),
      util::make_unique<DownloadFileCallback>(data)));
  data->request_ = std::move(request);
  MHD_Response* response = MHD_create_response_from_callback(
      node->getSize(), BUFFER_SIZE, data_provider, data, release_data);
  MHD_add_response_header(response, "Content-Type", "application/octet-stream");
  int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);
  return ret;
}

}  // namespace

MegaNz::MegaNz()
    : CloudProvider(util::make_unique<Auth>()),
      mega_(),
      authorized_(),
      engine_(device_()),
      daemon_port_(DEFAULT_DAEMON_PORT),
      daemon_(),
      temporary_directory_(".") {}

void MegaNz::initialize(InitData&& data) {
  {
    std::lock_guard<std::mutex> lock(auth_mutex());
    if (data.hints_.find("client_id") == std::end(data.hints_))
      mega_ = util::make_unique<MegaApi>("4T4khZxJ");
    else
      setWithHint(data.hints_, "client_id", [this](std::string v) {
        mega_ = util::make_unique<MegaApi>(v.c_str());
      });
    setWithHint(data.hints_, "daemon_port",
                [this](std::string v) { daemon_port_ = std::atoi(v.c_str()); });
    setWithHint(data.hints_, "temporary_directory",
                [this](std::string v) { temporary_directory_ = v; });
    daemon_ = std::unique_ptr<MHD_Daemon, std::function<void(MHD_Daemon*)>>(
        MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, daemon_port_, NULL,
                         NULL, &httpRequestCallback, this, MHD_OPTION_END),
        [](MHD_Daemon* daemon) { MHD_stop_daemon(daemon); });
    if (!daemon_) data.callback_->error(*this, "Failed to start daemon.");
  }
  CloudProvider::initialize(std::move(data));
}

std::string MegaNz::name() const { return "mega"; }

std::string MegaNz::endpoint() const { return "http://localhost"; }

IItem::Pointer MegaNz::rootDirectory() const {
  return util::make_unique<Item>("root", "/", IItem::FileType::Directory);
}

ICloudProvider::Hints MegaNz::hints() const {
  Hints result = {{"daemon_port", std::to_string(daemon_port_)},
                  {"temporary_directory", temporary_directory_}};
  auto t = CloudProvider::hints();
  result.insert(t.begin(), t.end());
  return result;
}

AuthorizeRequest::Pointer MegaNz::authorizeAsync() {
  return util::make_unique<Authorize>(
      shared_from_this(), [this](AuthorizeRequest* r) {
        if (!login(r)) {
          if (r->is_cancelled()) return false;
          if (callback()->userConsentRequired(*this) ==
              ICloudProvider::ICallback::Status::WaitForAuthorizationCode) {
            std::string code = r->getAuthorizationCode();
            auto data = creditentialsFromString(code);
            {
              std::lock_guard<std::mutex> mutex(auth_mutex());
              IAuth::Token::Pointer token = util::make_unique<IAuth::Token>();
              token->token_ =
                  data.first + Auth::SEPARATOR + passwordHash(data.second);
              token->refresh_token_ = token->token_;
              auth()->set_access_token(std::move(token));
            }
            if (!login(r)) return false;
          }
        }
        Authorize::Semaphore semaphore(r);
        RequestListener fetch_nodes_listener_(&semaphore);
        mega_->fetchNodes(&fetch_nodes_listener_);
        semaphore.wait();
        mega_->removeRequestListener(&fetch_nodes_listener_);
        if (fetch_nodes_listener_.status_ != RequestListener::SUCCESS) {
          return false;
        }
        authorized_ = true;
        return true;
      });
}

ICloudProvider::GetItemDataRequest::Pointer MegaNz::getItemDataAsync(
    const std::string& id, GetItemDataCallback callback) {
  auto r = util::make_unique<Request<IItem::Pointer>>(shared_from_this());
  r->set_resolver(
      [id, callback, this](Request<IItem::Pointer>* r) -> IItem::Pointer {
        if (!ensureAuthorized(r)) {
          callback(nullptr);
          return nullptr;
        }
        std::unique_ptr<mega::MegaNode> node(mega_->getNodeByPath(id.c_str()));
        if (!node) {
          callback(nullptr);
          return nullptr;
        }
        auto item = toItem(node.get());
        callback(item);
        return item;
      });
  return std::move(r);
}

ICloudProvider::ListDirectoryRequest::Pointer MegaNz::listDirectoryAsync(
    IItem::Pointer item, IListDirectoryCallback::Pointer callback) {
  auto r = util::make_unique<Request<std::vector<IItem::Pointer>>>(
      shared_from_this());
  r->set_resolver([this, item, callback](Request<std::vector<IItem::Pointer>>*
                                             r) -> std::vector<IItem::Pointer> {
    if (!ensureAuthorized(r)) {
      if (!r->is_cancelled()) callback->error("Authorization failed.");
      return {};
    }
    std::unique_ptr<mega::MegaNode> node(
        mega_->getNodeByPath(item->id().c_str()));
    std::vector<IItem::Pointer> result;
    if (node) {
      std::unique_ptr<mega::MegaNodeList> lst(mega_->getChildren(node.get()));
      if (lst) {
        for (int i = 0; i < lst->size(); i++) {
          auto item = toItem(lst->get(i));
          result.push_back(item);
          callback->receivedItem(item);
        }
      }
    }
    callback->done(result);
    return result;
  });
  return std::move(r);
}

ICloudProvider::DownloadFileRequest::Pointer MegaNz::downloadFileAsync(
    IItem::Pointer item, IDownloadFileCallback::Pointer callback) {
  auto r = util::make_unique<Request<void>>(shared_from_this());
  r->set_resolver(downloadResolver(item, callback));
  return std::move(r);
}

ICloudProvider::UploadFileRequest::Pointer MegaNz::uploadFileAsync(
    IItem::Pointer item, const std::string& filename,
    IUploadFileCallback::Pointer callback) {
  auto r = util::make_unique<Request<void>>(shared_from_this());
  r->set_resolver([this, item, callback, filename](Request<void>* r) {
    if (!ensureAuthorized(r)) {
      if (!r->is_cancelled()) callback->error("Authorization failed.");
      return;
    }
    std::string cache = temporaryFileName();
    {
      std::fstream mega_cache(cache.c_str(),
                              std::fstream::out | std::fstream::binary);
      if (!mega_cache)
        return callback->error("Couldn't open cache file " + cache);
      std::array<char, BUFFER_SIZE> buffer;
      while (auto length = callback->putData(buffer.data(), BUFFER_SIZE)) {
        if (r->is_cancelled()) return;
        mega_cache.write(buffer.data(), length);
      }
    }
    Request<void>::Semaphore semaphore(r);
    TransferListener listener(&semaphore);
    listener.upload_callback_ = callback;
    listener.request_ = r;
    std::unique_ptr<mega::MegaNode> node(
        mega_->getNodeByPath(item->id().c_str()));
    mega_->startUpload(cache.c_str(), node.get(), filename.c_str(), &listener);
    semaphore.wait();
    if (r->is_cancelled())
      while (listener.status_ == Listener::IN_PROGRESS) semaphore.wait();
    mega_->removeTransferListener(&listener);
    if (listener.status_ != Listener::SUCCESS) {
      if (!r->is_cancelled())
        callback->error("Upload error: " + listener.error_);
    } else
      callback->done();
    std::remove(cache.c_str());
  });
  return std::move(r);
}

ICloudProvider::DownloadFileRequest::Pointer MegaNz::getThumbnailAsync(
    IItem::Pointer item, IDownloadFileCallback::Pointer callback) {
  auto r = util::make_unique<Request<void>>(shared_from_this());
  r->set_resolver([this, item, callback](Request<void>* r) {
    if (!ensureAuthorized(r)) {
      if (!r->is_cancelled()) callback->error("Authorization failed.");
      return;
    }
    Request<void>::Semaphore semaphore(r);
    RequestListener listener(&semaphore);
    std::string cache = temporaryFileName();
    std::unique_ptr<mega::MegaNode> node(
        mega_->getNodeByPath(item->id().c_str()));
    mega_->getThumbnail(node.get(), cache.c_str(), &listener);
    semaphore.wait();
    if (r->is_cancelled())
      while (listener.status_ == Listener::IN_PROGRESS) semaphore.wait();
    mega_->removeRequestListener(&listener);
    if (listener.status_ == Listener::SUCCESS) {
      std::fstream cache_file(cache.c_str(),
                              std::fstream::in | std::fstream::binary);
      if (!cache_file)
        return callback->error("Couldn't open cache file " + cache);
      std::array<char, BUFFER_SIZE> buffer;
      do {
        cache_file.read(buffer.data(), BUFFER_SIZE);
        callback->receivedData(buffer.data(), cache_file.gcount());
      } while (cache_file.gcount() > 0);
      callback->done();
    } else {
      cloudstorage::DownloadFileRequest::generateThumbnail(r, item, callback);
    }
    std::remove(cache.c_str());
  });
  return std::move(r);
}

ICloudProvider::DeleteItemRequest::Pointer MegaNz::deleteItemAsync(
    IItem::Pointer item, DeleteItemCallback callback) {
  auto r = util::make_unique<Request<bool>>(shared_from_this());
  r->set_resolver([this, item, callback](Request<bool>* r) {
    if (!ensureAuthorized(r)) {
      callback(false);
      return false;
    }
    std::unique_ptr<mega::MegaNode> node(
        mega_->getNodeByPath(item->id().c_str()));
    Request<bool>::Semaphore semaphore(r);
    RequestListener listener(&semaphore);
    mega_->remove(node.get(), &listener);
    semaphore.wait();
    mega_->removeRequestListener(&listener);
    if (listener.status_ == Listener::SUCCESS) {
      callback(true);
      return true;
    } else {
      callback(false);
      return false;
    }
  });
  return std::move(r);
}

ICloudProvider::CreateDirectoryRequest::Pointer MegaNz::createDirectoryAsync(
    IItem::Pointer parent, const std::string& name,
    CreateDirectoryCallback callback) {
  auto r = util::make_unique<Request<IItem::Pointer>>(shared_from_this());
  r->set_resolver([=](Request<IItem::Pointer>* r) -> IItem::Pointer {
    if (!ensureAuthorized(r)) {
      callback(nullptr);
      return nullptr;
    }
    std::unique_ptr<mega::MegaNode> parent_node(
        mega_->getNodeByPath(parent->id().c_str()));
    if (!parent_node) {
      callback(nullptr);
      return nullptr;
    }
    Request<IItem::Pointer>::Semaphore semaphore(r);
    RequestListener listener(&semaphore);
    mega_->createFolder(name.c_str(), parent_node.get(), &listener);
    semaphore.wait();
    mega_->removeRequestListener(&listener);
    if (listener.status_ == Listener::SUCCESS) {
      std::unique_ptr<mega::MegaNode> node(
          mega_->getNodeByHandle(listener.node_));
      auto item = toItem(node.get());
      callback(item);
      return item;
    } else {
      callback(nullptr);
      return nullptr;
    }
  });
  return std::move(r);
}

ICloudProvider::MoveItemRequest::Pointer MegaNz::moveItemAsync(
    IItem::Pointer source, IItem::Pointer destination,
    MoveItemCallback callback) {
  auto r = util::make_unique<Request<bool>>(shared_from_this());
  r->set_resolver([=](Request<bool>* r) {
    if (!ensureAuthorized(r)) {
      callback(false);
      return false;
    }
    std::unique_ptr<mega::MegaNode> source_node(
        mega_->getNodeByPath(source->id().c_str()));
    std::unique_ptr<mega::MegaNode> destination_node(
        mega_->getNodeByPath(destination->id().c_str()));
    if (source_node && destination_node) {
      Request<bool>::Semaphore semaphore(r);
      RequestListener listener(&semaphore);
      mega_->moveNode(source_node.get(), destination_node.get(), &listener);
      semaphore.wait();
      mega_->removeRequestListener(&listener);
      if (listener.status_ == Listener::SUCCESS) {
        callback(true);
        return true;
      }
    }
    callback(false);
    return false;
  });
  return std::move(r);
}

ICloudProvider::RenameItemRequest::Pointer MegaNz::renameItemAsync(
    IItem::Pointer item, const std::string& name, RenameItemCallback callback) {
  auto r = util::make_unique<Request<bool>>(shared_from_this());
  r->set_resolver([=](Request<bool>* r) {
    if (!ensureAuthorized(r)) {
      callback(false);
      return false;
    }
    std::unique_ptr<mega::MegaNode> node(
        mega_->getNodeByPath(item->id().c_str()));
    if (node) {
      Request<bool>::Semaphore semaphore(r);
      RequestListener listener(&semaphore);
      mega_->renameNode(node.get(), name.c_str(), &listener);
      semaphore.wait();
      mega_->removeRequestListener(&listener);
      if (listener.status_ == Listener::SUCCESS) {
        callback(true);
        return true;
      }
    }
    callback(false);
    return false;
  });
  return std::move(r);
}

std::function<void(Request<void>*)> MegaNz::downloadResolver(
    IItem::Pointer item, IDownloadFileCallback::Pointer callback) {
  return [this, item, callback](Request<void>* r) {
    if (!ensureAuthorized(r)) {
      if (!r->is_cancelled()) callback->error("Authorization failed.");
      return;
    }
    std::unique_ptr<mega::MegaNode> node(
        mega_->getNodeByPath(item->id().c_str()));
    Request<void>::Semaphore semaphore(r);
    TransferListener listener(&semaphore);
    listener.download_callback_ = callback;
    listener.request_ = r;
    mega_->startStreaming(node.get(), 0, node->getSize(), &listener);
    semaphore.wait();
    if (r->is_cancelled())
      while (listener.status_ == Listener::IN_PROGRESS) semaphore.wait();
    mega_->removeTransferListener(&listener);
    if (listener.status_ != Listener::SUCCESS) {
      if (!r->is_cancelled()) callback->error("Failed to download");
    } else
      callback->done();
  };
}

bool MegaNz::login(Request<bool>* r) {
  Authorize::Semaphore semaphore(r);
  RequestListener auth_listener(&semaphore);
  auto data = creditentialsFromString(token());
  std::string mail = data.first;
  std::string private_key = data.second;
  std::unique_ptr<char[]> hash(
      mega_->getStringHash(private_key.c_str(), mail.c_str()));
  mega_->fastLogin(mail.c_str(), hash.get(), private_key.c_str(),
                   &auth_listener);
  semaphore.wait();
  mega_->removeRequestListener(&auth_listener);
  return auth_listener.status_ == Listener::SUCCESS;
}

std::string MegaNz::passwordHash(const std::string& password) {
  std::unique_ptr<char[]> hash(mega_->getBase64PwKey(password.c_str()));
  return std::string(hash.get());
}

IItem::Pointer MegaNz::toItem(MegaNode* node) {
  std::unique_ptr<char[]> path(mega_->getNodePath(node));
  auto item = util::make_unique<Item>(
      node->getName(), path.get(),
      node->isFolder() ? IItem::FileType::Directory : IItem::FileType::Unknown);
  std::unique_ptr<char[]> handle(node->getBase64Handle());
  item->set_url("http://localhost:" + std::to_string(daemon_port_) + "/?file=" +
                handle.get());
  return std::move(item);
}

std::string MegaNz::randomString(int length) {
  std::unique_lock<std::mutex> lock(mutex_);
  std::uniform_int_distribution<char> dist('a', 'z');
  std::string result;
  for (int i = 0; i < length; i++) result += dist(engine_);
  return result;
}

std::string MegaNz::temporaryFileName() {
  return temporary_directory_ + randomString(CACHE_FILENAME_LENGTH);
}

template <class T>
bool MegaNz::ensureAuthorized(Request<T>* r) {
  if (!authorized_)
    return r->reauthorize();
  else
    return true;
}

MegaNz::Auth::Auth() {}

std::string MegaNz::Auth::authorizeLibraryUrl() const {
  return redirect_uri() + "/login";
}

IHttpRequest::Pointer MegaNz::Auth::exchangeAuthorizationCodeRequest(
    std::ostream&) const {
  return nullptr;
}

IHttpRequest::Pointer MegaNz::Auth::refreshTokenRequest(std::ostream&) const {
  return nullptr;
}

IAuth::Token::Pointer MegaNz::Auth::exchangeAuthorizationCodeResponse(
    std::istream&) const {
  return nullptr;
}

IAuth::Token::Pointer MegaNz::Auth::refreshTokenResponse(std::istream&) const {
  return nullptr;
}

std::string MegaNz::Auth::get_login_page() const {
    return \
    "<script>"
    "function submitData(){"
        "window.location.href = \"" + redirect_uri_prefix() + "?code=\""
        " + encodeURIComponent($('#inputEmail').val() + '" \
        + std::string(SEPARATOR) + \
        "' + $('#inputPassword').val());"
        "return false;};"
    "</script>"
    "<h2 class=\"text-center\">Mega.Nz Login</h2>"
    "<h5>" + requesting_app_name() + " requires access to your Mega.Nz account "
        "in order to display the content of your cloud storage. This page is "
        "running locally and is hosted by your machine. The inserted data is "
        "going to be safely sent to <a href=\"mega.nz\">Mega.Nz</a> "
        "servers.</h5><br/>"
    "<form class=\"form-horizontal\" onsubmit=\"return submitData()\">"
    "<div class=\"form-group\">"
    "<label for=\"inputEmail\" "
        "class=\"col-sm-2 control-label\">Email</label>"
    "<div class=\"col-sm-10\">"
    "<input type=\"email\" "
        "class=\"form-control\" id=\"inputEmail\" placeholder=\"Email\">"
    "</div></div>"
    "<div class=\"form-group\">"
    "<label for=\"inputPassword\" "
        "class=\"col-sm-2 control-label\">Password</label>"
    "<div class=\"col-sm-10\">"
    "<input type=\"password\" "
        "class=\"form-control\" id=\"inputPassword\" placeholder=\"Password\">"
    "</div></div>"
    "<div class=\"form-group\"><div class=\"col-sm-offset-2 col-sm-10\">"
    "<button type=\"submit\" id=\"submit\" "
        "class=\"btn btn-default\">Sign in</button>"
    "</div></form>";
}

std::string MegaNz::Auth::get_success_page() const {
    // This requires the libcloudstorage to open the window, otherwise,
    // the browsers won't allow to close it.
    // "auth:1 Scripts may close only the windows that were opened by it."
    //return "<script>window.close()</script>";
    return "<h2 class=\"text-center\">Your login has been sent to "
            "<a href=\"mega.nz\">Mega.Nz</a> successfully</h2>";
}

MegaNz::Authorize::~Authorize() { cancel(); }

}  // namespace cloudstorage
