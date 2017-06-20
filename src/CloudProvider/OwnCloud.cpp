/*****************************************************************************
 * OwnCloud.cpp : OwnCloud implementation
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

#include "OwnCloud.h"

#include "Request/AuthorizeRequest.h"
#include "Utility/Item.h"

#include <cstring>

namespace cloudstorage {

OwnCloud::OwnCloud() : CloudProvider(util::make_unique<Auth>()) {}

IItem::Pointer OwnCloud::rootDirectory() const {
  return util::make_unique<Item>("root", "/", IItem::FileType::Directory);
}

void OwnCloud::initialize(InitData&& data) {
  unpackCreditentials(data.token_);
  CloudProvider::initialize(std::move(data));
}

std::string OwnCloud::name() const { return "owncloud"; }

std::string OwnCloud::endpoint() const { return api_url(); }

std::string OwnCloud::token() const {
  std::lock_guard<std::mutex> lock(auth_mutex());
  return user_ + "@" + owncloud_base_url_ + Auth::SEPARATOR + password_;
}

AuthorizeRequest::Pointer OwnCloud::authorizeAsync() {
  return util::make_unique<AuthorizeRequest>(
      shared_from_this(), [=](AuthorizeRequest* r) -> bool {
        if (callback()->userConsentRequired(*this) !=
            ICallback::Status::WaitForAuthorizationCode)
          return false;
        unpackCreditentials(r->getAuthorizationCode());
        return true;
      });
}

ICloudProvider::CreateDirectoryRequest::Pointer OwnCloud::createDirectoryAsync(
    IItem::Pointer parent, const std::string& name,
    CreateDirectoryCallback callback) {
  auto r = util::make_unique<Request<IItem::Pointer>>(shared_from_this());
  r->set_resolver([=](Request<IItem::Pointer>* r) -> IItem::Pointer {
    std::stringstream response;
    int code = r->sendRequest(
        [=](std::ostream&) {
          return http()->create(
              api_url() + "/remote.php/webdav" + parent->id() + name + "/",
              "MKCOL");
        },
        response);
    if (IHttpRequest::isSuccess(code)) {
      IItem::Pointer item = util::make_unique<Item>(
          name, parent->id() + name + "/", IItem::FileType::Directory);
      callback(item);
      return item;
    } else {
      callback(nullptr);
      return nullptr;
    }
  });
  return std::move(r);
}

IHttpRequest::Pointer OwnCloud::getItemDataRequest(const std::string& id,
                                                   std::ostream&) const {
  auto request =
      http()->create(api_url() + "/remote.php/webdav" + id, "PROPFIND");
  request->setHeaderParameter("Depth", "0");
  return request;
}

IHttpRequest::Pointer OwnCloud::listDirectoryRequest(const IItem& item,
                                                     const std::string&,
                                                     std::ostream&) const {
  auto request =
      http()->create(api_url() + "/remote.php/webdav" + item.id(), "PROPFIND");
  request->setHeaderParameter("Depth", "1");
  return request;
}

IHttpRequest::Pointer OwnCloud::uploadFileRequest(const IItem& directory,
                                                  const std::string& filename,
                                                  std::ostream&,
                                                  std::ostream&) const {
  return http()->create(api_url() + "/remote.php/webdav" + directory.id() +
                            http()->escape(filename),
                        "PUT");
}

IHttpRequest::Pointer OwnCloud::downloadFileRequest(const IItem& item,
                                                    std::ostream&) const {
  return http()->create(static_cast<const Item&>(item).url(), "GET");
}

IHttpRequest::Pointer OwnCloud::deleteItemRequest(const IItem& item,
                                                  std::ostream&) const {
  auto request =
      http()->create(api_url() + "/remote.php/webdav" + item.id(), "DELETE");
  return request;
}

IHttpRequest::Pointer OwnCloud::moveItemRequest(const IItem& source,
                                                const IItem& destination,
                                                std::ostream&) const {
  auto request =
      http()->create(api_url() + "/remote.php/webdav" + source.id(), "MOVE");
  request->setHeaderParameter(
      "Destination", "https://" + owncloud_base_url_ + "/remote.php/webdav" +
                         destination.id() + "/" + source.filename());
  return request;
}

IHttpRequest::Pointer OwnCloud::renameItemRequest(const IItem& item,
                                                  const std::string& name,
                                                  std::ostream&) const {
  auto request =
      http()->create(api_url() + "/remote.php/webdav" + item.id(), "MOVE");
  request->setHeaderParameter(
      "Destination", "https://" + owncloud_base_url_ + "/remote.php/webdav" +
                         getPath(item.id()) + "/" + name);
  return request;
}

IItem::Pointer OwnCloud::getItemDataResponse(std::istream& stream) const {
  std::stringstream sstream;
  sstream << stream.rdbuf();
  tinyxml2::XMLDocument document;
  if (document.Parse(sstream.str().c_str(), sstream.str().size()) !=
      tinyxml2::XML_SUCCESS)
    return nullptr;
  return toItem(document.RootElement()->FirstChild());
}

std::vector<IItem::Pointer> OwnCloud::listDirectoryResponse(
    std::istream& stream, std::string&) const {
  std::stringstream sstream;
  sstream << stream.rdbuf();
  tinyxml2::XMLDocument document;
  if (document.Parse(sstream.str().c_str(), sstream.str().size()) !=
      tinyxml2::XML_SUCCESS)
    return {};
  if (document.RootElement()->FirstChild() == nullptr) return {};

  std::vector<IItem::Pointer> result;
  for (auto child = document.RootElement()->FirstChild()->NextSibling(); child;
       child = child->NextSibling()) {
    result.push_back(toItem(child));
  }
  return result;
}

std::string OwnCloud::api_url() const {
  std::lock_guard<std::mutex> lock(auth_mutex());
  return "https://" + user_ + ":" + password_ + "@" + owncloud_base_url_;
}

IItem::Pointer OwnCloud::toItem(const tinyxml2::XMLNode* node) const {
  std::string id = node->FirstChildElement("d:href")->GetText();
  id = id.substr(strlen("/remote.php/webdav"));
  IItem::FileType type = IItem::FileType::Unknown;
  if (id.back() == '/') type = IItem::FileType::Directory;
  std::string filename = id;
  if (filename.back() == '/') filename.pop_back();
  filename = filename.substr(filename.find_last_of('/') + 1);
  auto item = util::make_unique<Item>(http()->unescape(filename), id, type);
  item->set_url(api_url() + "/remote.php/webdav" + id);
  return std::move(item);
}

bool OwnCloud::reauthorize(int code) const {
  return CloudProvider::reauthorize(code) || owncloud_base_url_.empty();
}

void OwnCloud::authorizeRequest(IHttpRequest&) const {}

void OwnCloud::unpackCreditentials(const std::string& code) {
  std::unique_lock<std::mutex> lock(auth_mutex());
  auto separator = code.find_first_of(Auth::SEPARATOR);
  auto at_position = code.find_last_of('@', separator);
  if (at_position == std::string::npos || separator == std::string::npos)
    return;
  user_ = code.substr(0, at_position);
  owncloud_base_url_ =
      code.substr(at_position + 1, separator - at_position - 1);
  password_ = code.substr(separator + strlen(Auth::SEPARATOR));
}

OwnCloud::Auth::Auth() {}

std::string OwnCloud::Auth::authorizeLibraryUrl() const {
  return redirect_uri() + "/login";
}

IHttpRequest::Pointer OwnCloud::Auth::exchangeAuthorizationCodeRequest(
    std::ostream&) const {
  return nullptr;
}

IHttpRequest::Pointer OwnCloud::Auth::refreshTokenRequest(std::ostream&) const {
  return nullptr;
}

IAuth::Token::Pointer OwnCloud::Auth::exchangeAuthorizationCodeResponse(
    std::istream&) const {
  return nullptr;
}

IAuth::Token::Pointer OwnCloud::Auth::refreshTokenResponse(
    std::istream&) const {
  return nullptr;
}

std::string OwnCloud::Auth::get_login_page() const {
    return \
    "<script>"
    "function submitData(){"
        "window.location.href = \"" + redirect_uri_prefix() + "?code=\""
        " + encodeURIComponent($('#inputUsername').val() + '@' "
        " + $('#inputHost').val() + '" + std::string(SEPARATOR) + \
        "' + $('#inputPassword').val()) + \"&accepted=true\";"
        "return false;};"
    "</script>"
    "<h2 class=\"text-center\">OwnCloud Login</h2>"
    "<h5>" + requesting_app_name() + " requires to access your Mega.Nz account "
        "in order to display the content of your cloud storage. This page is "
        "running locally and hosted by your machine. The inserted is going to "
        "be safely sent to <a href=\"https://owncloud.org/\">OwnCloud</a> "
        "host.</h5><br/>"
    "<form class=\"form-horizontal\" onsubmit=\"return submitData()\">"
    "<div class=\"form-group\">"
    "<label for=\"inputUsername\" "
        "class=\"col-sm-2 control-label\">Username</label>"
    "<div class=\"col-sm-10\">"
    "<input type=\"text\" "
        "class=\"form-control\" id=\"inputUsername\" placeholder=\"Username\">"
    "</div></div>"
    "<div class=\"form-group\">"
    "<label for=\"inputHost\" "
        "class=\"col-sm-2 control-label\">Host</label>"
    "<div class=\"col-sm-10\">"
    "<input type=\"text\" "
        "class=\"form-control\" id=\"inputHost\" placeholder=\"Host\">"
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

std::string OwnCloud::Auth::get_success_page() const {
    // This requires the libcloudstorage to open the window, otherwise,
    // the browsers won't allow to close it.
    // "auth:1 Scripts may close only the windows that were opened by it."
    //return "<script>window.close()</script>";
    return "<h2 class=\"text-center\">Your login has been sent to "
            "<a href=\"https://owncloud.org/\">OwnCloud</a> host "
            "successfully</h2>";
}

}  // namespace cloudstorage
