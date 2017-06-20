/*****************************************************************************
 * AmazonS3.cpp : AmazonS3 implementation
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

#include "AmazonS3.h"

#include <tinyxml2.h>
#include <algorithm>
#include <iomanip>
#include <map>

const std::map<std::string, std::string> regions_list_ = {
    {"us-east-2", "US East (Ohio)"},
    {"us-east-1", "US East (N. Virginia)"},
    {"us-west-1", "US West (N. California)"},
    {"us-west-2", "US West (Oregon)"},
    {"ca-central-1", "Canada (Central)"},
    {"ap-south-1", "Asia Pacific (Mumbai)"},
    {"ap-northeast-2", "Asia Pacific (Seoul)"},
    {"ap-southeast-1", "Asia Pacific (Singapore)"},
    {"ap-southeast-2", "Asia Pacific (Sydney)"},
    {"ap-northeast-1", "Asia Pacific (Tokyo)"},
    {"eu-central-1", "EU (Frankfurt)"},
    {"eu-west-1", "EU (Ireland)"},
    {"eu-west-2", "EU (London)"},
    {"sa-east-1", "South America (São Paulo)"}
};

using namespace std::placeholders;

namespace cloudstorage {

namespace {

std::string escapePath(IHttp* http, const std::string& str) {
  std::string data = http->escape(str);
  std::string slash = http->escape("/");
  std::string result;
  for (uint32_t i = 0; i < data.size();)
    if (data.substr(i, slash.length()) == slash) {
      result += "/";
      i += slash.length();
    } else {
      result += data[i];
      i++;
    }
  return result;
}

bool rename(Request<bool>* r, std::string dest_id, std::string source_id,
            std::string region, IHttp* http) {
  if (!source_id.empty() && source_id.back() != '/') {
    std::stringstream output;
    int code = r->sendRequest(
        [=](std::ostream&) {
          auto dest_data = AmazonS3::split(dest_id);
          auto request = http->create("https://" + dest_data.first + ".s3." +
                                          region + ".amazonaws.com/" +
                                          escapePath(http, dest_data.second),
                                      "PUT");
          auto source_data = AmazonS3::split(source_id);
          request->setHeaderParameter(
              "x-amz-copy-source",
              escapePath(http,
                         "/" + source_data.first + "/" + source_data.second));
          return request;
        },
        output);
    if (!IHttpRequest::isSuccess(code)) return false;
  } else {
    auto directory = r->provider()
                         ->getItemDataAsync(source_id, [](IItem::Pointer) {})
                         ->result();
    Request<bool>::Semaphore semaphore(r);
    auto children_request = r->provider()->listDirectoryAsync(
        directory, [&semaphore](const std::vector<IItem::Pointer>&) {
          semaphore.notify();
        });
    semaphore.wait();
    if (r->is_cancelled()) {
      children_request->cancel();
      return false;
    }
    for (auto item : children_request->result())
      if (!rename(r, dest_id + "/" + item->filename(), item->id(), region,
                  http))
        return false;
  }
  std::stringstream output;
  int code = r->sendRequest(
      [=](std::ostream&) {
        auto data = AmazonS3::split(source_id);
        return http->create("https://" + data.first + ".s3." + region +
                                ".amazonaws.com/" +
                                escapePath(http, data.second),
                            "DELETE");
      },
      output);
  if (!IHttpRequest::isSuccess(code)) return false;
  return true;
}

std::string host(std::string url) {
  const char* http = "https://";
  return url.substr(strlen(http),
                    url.find_first_of('/', strlen(http)) - strlen(http));
}

std::string path(std::string url) {
  int length = host(url).length();
  return url.substr(strlen("https://") + length);
}

std::string currentDate() {
  auto now = std::chrono::system_clock::now();
  auto in_time_t = std::chrono::system_clock::to_time_t(now);

  std::stringstream ss;
  ss << std::put_time(std::gmtime(&in_time_t), "%Y%m%d");
  return ss.str();
}

std::string currentDateAndTime() {
  auto now = std::chrono::system_clock::now();
  auto in_time_t = std::chrono::system_clock::to_time_t(now);

  std::stringstream ss;
  ss << std::put_time(std::gmtime(&in_time_t), "%Y%m%dT%H%M%SZ");
  return ss.str();
}

}  // namespace

AmazonS3::AmazonS3()
    : CloudProvider(util::make_unique<Auth>())
{
}

void AmazonS3::unpackCredentials(const std::string& code) {
  auto separator = code.find_first_of(Auth::SEPARATOR);
  auto at_position = code.find_last_of('@', separator);
  if (at_position == std::string::npos || separator == std::string::npos)
    return;
  access_id_ = code.substr(0, at_position);
  region_ =
      code.substr(at_position + 1, separator - at_position - 1);
  secret_ = code.substr(separator + strlen(Auth::SEPARATOR));
}

void AmazonS3::initialize(InitData&& init_data) {
  {
    std::unique_lock<std::mutex> lock(auth_mutex());
    unpackCredentials(init_data.token_);
  }
  CloudProvider::initialize(std::move(init_data));
}

std::string AmazonS3::token() const {
  return access_id() + "@" + region() + Auth::SEPARATOR + secret();
}

std::string AmazonS3::name() const { return "amazons3"; }

std::string AmazonS3::endpoint() const {
  return "https://s3-" + region_ + ".amazonaws.com";
}

ICloudProvider::Hints AmazonS3::hints() const {
  Hints result = {{"aws_region", region_}};
  auto t = CloudProvider::hints();
  result.insert(t.begin(), t.end());
  return result;
}

AuthorizeRequest::Pointer AmazonS3::authorizeAsync() {
  return util::make_unique<AuthorizeRequest>(
      shared_from_this(), [=](AuthorizeRequest* r) -> bool {
        if (callback()->userConsentRequired(*this) !=
            ICallback::Status::WaitForAuthorizationCode)
          return false;
        unpackCredentials(r->getAuthorizationCode());
        return true;
      });
}

ICloudProvider::MoveItemRequest::Pointer AmazonS3::moveItemAsync(
    IItem::Pointer source, IItem::Pointer destination,
    MoveItemCallback callback) {
  auto r = util::make_unique<Request<bool>>(shared_from_this());
  r->set_resolver([=](Request<bool>* r) -> bool {
    bool success = rename(r, destination->id() + source->filename(),
                          source->id(), region_, http());
    callback(success);
    return success;
  });
  return std::move(r);
}

ICloudProvider::RenameItemRequest::Pointer AmazonS3::renameItemAsync(
    IItem::Pointer item, const std::string& name, RenameItemCallback callback) {
  auto r = util::make_unique<Request<bool>>(shared_from_this());
  r->set_resolver([=](Request<bool>* r) -> bool {
    std::string path = split(item->id()).second;
    if (!path.empty() && path.back() == '/') path.pop_back();
    if (path.find_first_of('/') == std::string::npos)
      path = split(item->id()).first + Auth::SEPARATOR;
    else
      path = split(item->id()).first + Auth::SEPARATOR + getPath(path) + "/";
    bool success = rename(r, path + name, item->id(), region_, http());
    callback(success);
    return success;
  });
  return std::move(r);
}

ICloudProvider::CreateDirectoryRequest::Pointer AmazonS3::createDirectoryAsync(
    IItem::Pointer parent, const std::string& name,
    CreateDirectoryCallback callback) {
  auto r = util::make_unique<Request<IItem::Pointer>>(shared_from_this());
  r->set_resolver([=](Request<IItem::Pointer>* r) -> IItem::Pointer {
    std::stringstream output;
    int code = r->sendRequest(
        [=](std::ostream&) {
          auto data = split(parent->id());
          return http()->create(
              "https://" + data.first + ".s3." + region_ + ".amazonaws.com/" +
                  escapePath(http(), data.second + name + "/"),
              "PUT");
        },
        output);
    if (!IHttpRequest::isSuccess(code)) {
      callback(nullptr);
      return nullptr;
    } else {
      auto path = getPath(parent->id());
      if (!split(path).second.empty()) path += "/";
      auto item = std::make_shared<Item>(name, path + name + "/",
                                         IItem::FileType::Directory);
      callback(item);
      return item;
    }

  });
  return std::move(r);
}

ICloudProvider::DeleteItemRequest::Pointer AmazonS3::deleteItemAsync(
    IItem::Pointer item, DeleteItemCallback callback) {
  auto r = util::make_unique<Request<bool>>(shared_from_this());
  r->set_resolver([=](Request<bool>* r) -> bool {
    if (item->type() == IItem::FileType::Directory) {
      Request<bool>::Semaphore semaphore(r);
      auto children_request = r->provider()->listDirectoryAsync(
          item, [&semaphore](const std::vector<IItem::Pointer>&) {
            semaphore.notify();
          });
      semaphore.wait();
      if (r->is_cancelled()) {
        children_request->cancel();
        callback(false);
        return false;
      }
      for (auto child : children_request->result()) {
        auto delete_request =
            deleteItemAsync(child, [&](bool) { semaphore.notify(); });
        semaphore.wait();
        if (r->is_cancelled()) {
          delete_request->cancel();
          callback(false);
          return false;
        }
      }
    }
    std::stringstream output;
    int code = r->sendRequest(
        [=](std::ostream&) {
          auto data = split(item->id());
          return http()->create("https://" + data.first + ".s3." + region_ +
                                    ".amazonaws.com/" +
                                    escapePath(http(), data.second),
                                "DELETE");
        },
        output);
    if (!IHttpRequest::isSuccess(code)) {
      callback(false);
      return false;
    }
    callback(true);
    return true;
  });
  return std::move(r);
}

ICloudProvider::GetItemDataRequest::Pointer AmazonS3::getItemDataAsync(
    const std::string& id, GetItemCallback callback) {
  auto r = util::make_unique<Request<IItem::Pointer>>(shared_from_this());
  r->set_resolver([=](Request<IItem::Pointer>* r) -> IItem::Pointer {
    if (access_id().empty() || secret().empty()) r->reauthorize();
    auto data = split(id);
    auto item = std::make_shared<Item>(
        getFilename(data.second), id,
        (data.second.empty() || data.second.back() == '/')
            ? IItem::FileType::Directory
            : IItem::FileType::Unknown);
    if (item->type() != IItem::FileType::Directory)
      item->set_url(getUrl(*item));
    callback(item);
    return item;
  });
  return std::move(r);
}

IHttpRequest::Pointer AmazonS3::listDirectoryRequest(
    const IItem& item, const std::string& page_token, std::ostream&) const {
  if (item.id() == rootDirectory()->id())
    return http()->create(endpoint() + "/", "GET");
  else {
    auto data = split(item.id());
    auto request = http()->create(
        "https://" + data.first + ".s3." + region_ + ".amazonaws.com/", "GET");
    request->setParameter("list-type", "2");
    request->setParameter("prefix", data.second);
    request->setParameter("delimiter", "/");
    if (!page_token.empty())
      request->setParameter("continuation-token", page_token);
    return request;
  }
}

IHttpRequest::Pointer AmazonS3::uploadFileRequest(const IItem& directory,
                                                  const std::string& filename,
                                                  std::ostream&,
                                                  std::ostream&) const {
  auto data = split(directory.id());
  return http()->create("https://" + data.first + ".s3." + region_ +
                            ".amazonaws.com/" +
                            escapePath(http(), data.second + filename),
                        "PUT");
}

IHttpRequest::Pointer AmazonS3::downloadFileRequest(const IItem& item,
                                                    std::ostream&) const {
  auto data = split(item.id());
  return http()->create("https://" + data.first + ".s3." + region_ +
                            ".amazonaws.com/" + escapePath(http(), data.second),
                        "GET");
}

std::vector<IItem::Pointer> AmazonS3::listDirectoryResponse(
    std::istream& stream, std::string& next_page_token) const {
  std::stringstream sstream;
  sstream << stream.rdbuf();
  tinyxml2::XMLDocument document;
  if (document.Parse(sstream.str().c_str(), sstream.str().size()) !=
      tinyxml2::XML_SUCCESS)
    return {};
  std::vector<IItem::Pointer> result;
  if (auto buckets = document.RootElement()->FirstChildElement("Buckets")) {
    for (auto child = buckets->FirstChild(); child;
         child = child->NextSibling()) {
      std::string name = child->FirstChildElement("Name")->GetText();
      auto item = util::make_unique<Item>(name, name + Auth::SEPARATOR,
                                          IItem::FileType::Directory);
      result.push_back(std::move(item));
    }
  } else if (document.RootElement()->FirstChildElement("Name")) {
    std::string bucket =
        document.RootElement()->FirstChildElement("Name")->GetText();
    for (auto child = document.RootElement()->FirstChildElement("Contents");
         child; child = child->NextSiblingElement("Contents")) {
      if (child->FirstChildElement("Size")->GetText() == std::string("0"))
        continue;
      std::string id = child->FirstChildElement("Key")->GetText();
      auto item = util::make_unique<Item>(getFilename(id),
                                          bucket + Auth::SEPARATOR + id,
                                          IItem::FileType::Unknown);
      item->set_url(getUrl(*item));
      result.push_back(std::move(item));
    }
    for (auto child =
             document.RootElement()->FirstChildElement("CommonPrefixes");
         child; child = child->NextSiblingElement("CommonPrefixes")) {
      std::string id = child->FirstChildElement("Prefix")->GetText();
      auto item = util::make_unique<Item>(getFilename(id),
                                          bucket + Auth::SEPARATOR + id,
                                          IItem::FileType::Directory);
      result.push_back(std::move(item));
    }
    if (document.RootElement()->FirstChildElement("IsTruncated")->GetText() ==
        std::string("true")) {
      next_page_token = document.RootElement()
                            ->FirstChildElement("NextContinuationToken")
                            ->GetText();
    }
  }
  return result;
}

void AmazonS3::authorizeRequest(IHttpRequest& request) const {
  if (!crypto()) {
    callback()->error(*this, "No crypto functions provided.");
    return;
  }
  std::string current_date = currentDate();
  std::string time = currentDateAndTime();
  std::string scope = current_date + "/" + region_ + "/s3/aws4_request";
  request.setParameter("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
  request.setParameter("X-Amz-Credential", access_id() + "/" + scope);
  request.setParameter("X-Amz-Date", time);
  request.setParameter("X-Amz-Expires", "86400");
  request.setHeaderParameter("host", host(request.url()));

  std::vector<std::pair<std::string, std::string>> header_parameters;
  for (auto q : request.headerParameters())
    header_parameters.push_back({q.first, q.second});
  std::sort(header_parameters.begin(), header_parameters.end());

  std::string signed_headers;
  {
    bool first = false;
    for (auto q : header_parameters) {
      if (first)
        signed_headers += ";";
      else
        first = true;
      signed_headers += q.first;
    }
    request.setParameter("X-Amz-SignedHeaders", signed_headers);
  }

  std::vector<std::pair<std::string, std::string>> query_parameters;
  for (auto q : request.parameters())
    query_parameters.push_back({q.first, q.second});
  std::sort(query_parameters.begin(), query_parameters.end());

  std::string canonical_request =
      request.method() + "\n" + path(request.url()) + "\n";

  bool first = false;
  for (auto q : query_parameters) {
    if (first)
      canonical_request += "&";
    else
      first = true;
    canonical_request +=
        http()->escape(q.first) + "=" + http()->escape(q.second);
  }
  canonical_request += "\n";

  for (auto q : header_parameters)
    canonical_request += http()->escape(q.first) + ":" + q.second + "\n";
  canonical_request += "\n";
  canonical_request += signed_headers + "\n";
  canonical_request += "UNSIGNED-PAYLOAD";

  auto hash = std::bind(&ICrypto::sha256, crypto(), _1);
  auto sign = std::bind(&ICrypto::hmac_sha256, crypto(), _1, _2);
  auto hex = std::bind(&ICrypto::hex, crypto(), _1);

  std::string string_to_sign = "AWS4-HMAC-SHA256\n" + time + "\n" + scope +
                               "\n" + hex(hash(canonical_request));
  std::string key =
      sign(sign(sign(sign("AWS4" + secret(), current_date), region_), "s3"),
           "aws4_request");
  std::string signature = hex(sign(key, string_to_sign));

  request.setParameter("X-Amz-Signature", signature);

  auto params = request.parameters();
  for (auto p : params) request.setParameter(p.first, http()->escape(p.second));
}

bool AmazonS3::reauthorize(int code) const {
  return CloudProvider::reauthorize(code) || code == 403 ||
         access_id().empty() || secret().empty();
}

std::string AmazonS3::access_id() const {
  std::lock_guard<std::mutex> lock(auth_mutex());
  return access_id_;
}

std::string AmazonS3::secret() const {
  std::lock_guard<std::mutex> lock(auth_mutex());
  return secret_;
}

std::string AmazonS3::region() const {
  std::lock_guard<std::mutex> lock(auth_mutex());
  return region_;
}

std::pair<std::string, std::string> AmazonS3::split(const std::string& str) {
  return creditentialsFromString(str);
}

std::string AmazonS3::getUrl(const Item& item) const {
  auto data = split(item.id());
  auto request =
      http()->create("https://" + data.first + ".s3." + region_ +
                         ".amazonaws.com/" + escapePath(http(), data.second),
                     "GET");
  authorizeRequest(*request);
  std::string parameters;
  for (const auto& p : request->parameters())
    parameters += p.first + "=" + p.second + "&";
  return request->url() + "?" + parameters;
}

AmazonS3::Auth::Auth() {}

std::string AmazonS3::Auth::authorizeLibraryUrl() const {
  return redirect_uri() + "/login";
}

IHttpRequest::Pointer AmazonS3::Auth::exchangeAuthorizationCodeRequest(
    std::ostream&) const {
  return nullptr;
}

IHttpRequest::Pointer AmazonS3::Auth::refreshTokenRequest(std::ostream&) const {
  return nullptr;
}

IAuth::Token::Pointer AmazonS3::Auth::exchangeAuthorizationCodeResponse(
    std::istream&) const {
  return nullptr;
}

IAuth::Token::Pointer AmazonS3::Auth::refreshTokenResponse(
    std::istream&) const {
  return nullptr;
}

std::string AmazonS3::Auth::get_login_page() const {
    std::string page = "<script>"
    "function submitData(){"
        "window.location.href = \"" + redirect_uri_prefix() + "?code=\""
        " + encodeURIComponent($('#inputAccessKey').val() + '@'"
        " + $('#inputRegion').val() + '" \
        + std::string(SEPARATOR) + \
        "' + $('#inputSecretKey').val()) + \"&accepted=true\";"
        "return false;};"
    "</script>"
    "<h2 class=\"text-center\">Amazon S3 Login</h2>"
    "<h5>" + requesting_app_name() + " requires access to your Amazon S3 "
        "account in order to display the content of your cloud storage.<br/>"
        "Amazon S3 requires generating an access and a secret token in order "
        "to be used in external applications. To generate those tokens, go to "
        "\"My security credentials\", then \"Access Keys\" and create them."
        "</h5><br/>"
    "<form class=\"form-horizontal\" onsubmit=\"return submitData()\">";

    // Regions
    page += "<div class=\"form-group\">"
    "<label for=\"inputRegion\" "
        "class=\"col-sm-2 control-label\">Region</label>"
    "<div class=\"col-sm-10\">"
    "<select id=\"inputRegion\" class=\"form-control\">";

    for (const auto& region : regions_list_) {
        page += "<option value=\""+ region.first + "\">" + \
                region.second + "</option>";
    }
    page += "</select>"
        "</div></div>";

    // Access and Secret Key
    page += "<div class=\"form-group\">"
    "<label for=\"inputAccessKey\" "
        "class=\"col-sm-2 control-label\">Access Key</label>"
    "<div class=\"col-sm-10\">"
    "<input type=\"text\" "
        "class=\"form-control\" id=\"inputAccessKey\" placeholder=\"Access Key ID\">"
    "</div></div>"
    "<div class=\"form-group\">"
    "<label for=\"inputSecretKey\" "
        "class=\"col-sm-2 control-label\">Secret Key</label>"
    "<div class=\"col-sm-10\">"
    "<input type=\"password\" "
        "class=\"form-control\" id=\"inputSecretKey\" placeholder=\"Secret Access Key\">"
    "</div></div>"
    "<div class=\"form-group\"><div class=\"col-sm-offset-2 col-sm-10\">"
    "<button type=\"submit\" id=\"submit\" "
        "class=\"btn btn-default\">Sign in</button>"
    "</div></form>"
    "<br/><br/><h5>This page is running locally and "
        "is hosted by your machine. The inserted data is going to be safely "
        "sent to <a href=\"https://aws.amazon.com/s3/\">Amazon S3</a> "
        "servers.</h5>";

    
    return page;
}

std::string AmazonS3::Auth::get_success_page() const {
    // This requires the libcloudstorage to open the window, otherwise,
    // the browsers won't allow to close it.
    // "auth:1 Scripts may close only the windows that were opened by it."
    //return "<script>window.close()</script>";
    return "<h2 class=\"text-center\">Your login has been sent to "
            "<a href=\"https://aws.amazon.com/s3/\">Amazon S3</a> server "
            "successfully</h2>";
}

}  // namespace cloudstorage
