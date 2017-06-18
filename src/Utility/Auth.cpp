/*****************************************************************************
 * Auth.cpp : Auth implementation
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

#include "Auth.h"

#include <json/json.h>
#include <fstream>
#include <sstream>
#include <iostream>

#include "Utility.h"

const uint16_t DEFAULT_REDIRECT_URI_PORT = 8080;
const std::string DEFAULT_REDIRECT_URI_PREFIX = "/auth";

const std::string HEAD = \
    "<head><meta name=\"Author\" content=\"VideoLAN\" />"
    "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />"
    "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\" />"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />"
    "<title>VLC Local Authentication Server</title>"
    "<script src='//ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js' "
        "type='text/javascript'></script>"
    "<script async=\"async\" src=\"//images.videolan.org/js/bootstrap.min.js\" "
        "type=\"text/javascript\"></script>"
    "<link rel=\"stylesheet\" type=\"text/css\" "
        "href=\"//images.videolan.org/style/bootstrap.min.css\" />"
    "<link rel=\"stylesheet\" type=\"text/css\" "
        "href=\"//images.videolan.org/style/style.min.css\" />"
    "</head>";

const std::string NAVBAR = \
    "<nav id=\"nav\" class=\"navbar navbar-default navbar-fixed-top\">"
    "<div class=\"container\">"
    "<div class=\"navbar-header\">"
    "<a class=\"navbar-brand\" href=\"//www.videolan.org/\">"
    "<img src='//images.videolan.org/images/logoBlue.png' "
        "alt='VideoLAN association' />"
    "</a><a class=\"navbar-brand\" style=\"padding: 15px 15px\">"
        "Libcloudstorage Local Server</a>"
    "<button type=\"button\" class=\"navbar-toggle collapsed\" "
        "data-toggle=\"collapse\" data-target=\"#main-navbar\" "
        "aria-expanded=\"false\">"
    "<span class=\"sr-only\">Toggle navigation</span>"
    "<span class=\"icon-bar\"></span>"
    "<span class=\"icon-bar\"></span>"
    "<span class=\"icon-bar\"></span>"
    "</button>"
    "</div>"
    "</div>"
    "</nav>";

namespace cloudstorage {
namespace {

struct HttpServerData {
  const Auth* obj_;
  std::string code_;
  std::string code_parameter_name_;
  std::string error_parameter_name_;
  uint16_t port_;
  enum { Awaiting, Accepted, Denied } state_;
  Semaphore* semaphore_;
};

std::string sendHttpRequestFromJavaScript(const Json::Value& json) {
  std::stringstream stream;
  stream << "<script>$.ajax(" << json << ")</script>";
  return stream.str();
}

std::string requestCallback(IHttpd::RequestData * rdata) {
    HttpServerData* data = static_cast<HttpServerData*>(rdata->custom_data);
    const Auth* auth = data->obj_;
    std::string page = "<html>" + HEAD + "<body class=\"new-design\">";

    std::string url = rdata->url;
    // Normalize the URL
    if (url.at(url.size() - 1) == '/')
        url.pop_back();

    if (url == auth->redirect_uri_prefix() + "/login") {
        // Requesting the login page
        page += auth->get_login_page();
    } else if (url == auth->redirect_uri_prefix()) {
        // Submitting an authentication request
        std::string code = auth->httpd()->
                getArgument(rdata, data->code_parameter_name_);
        std::string error = auth->httpd()->
                getArgument(rdata, data->error_parameter_name_);
        std::string accepted = auth->httpd()->
                getArgument(rdata, "accepted");
        if (!accepted.empty()) {
            if (!code.empty()) data->code_ = code;
            if (accepted == "true") {
                data->state_ = HttpServerData::Accepted;
            } else
                data->state_ = HttpServerData::Denied;
            data->semaphore_->notify();
        } else if (!code.empty()) {
            Json::Value json;
            json["data"]["accepted"] = "true";
            page += auth->get_success_page() +
                    sendHttpRequestFromJavaScript(json);
        } else if (!error.empty()) {
            Json::Value json;
            json["data"]["accepted"] = "false";
            page += auth->get_error_page() +
                    sendHttpRequestFromJavaScript(json);
        } else {
            page += auth->get_error_page("Bad request");
        }
    } else {
        // Requested a non-existing page
        page += auth->get_error_page("Page not found");
    }

    page += "</body></html>";
    return page;
}

}  // namespace

Auth::Auth() : redirect_uri_port_(DEFAULT_REDIRECT_URI_PORT), http_(), httpd_(),
        redirect_uri_prefix_(DEFAULT_REDIRECT_URI_PREFIX) {}

void Auth::initialize(IHttp* http, IHttpd* httpd) { http_ = http; httpd_ = httpd; }

std::string Auth::get_login_page() const {
    return \
    "libcloudstorage login page"
    "<table>"
    "<tr><td>Login:</td><td><input id='login'></td></tr>"
    "<tr><td>Password:</td><td><input id='password' type='password'></td></tr>"
    "<tr><td><input id='submit' type='button' value='Login'></td></tr>"
    "<script>"
    " $(function() {"
    "   $('#submit').click(function() {"
    "     $.ajax({"
    "       url: '/',"
    "       method: 'GET',"
    "       data: {"
    "         'code' : $('#login').val() + '" +
    std::string(cloudstorage::Auth::SEPARATOR) +
    "' + $('#password').val(),"
    "         'accepted' : 'true'"
    "       }"
    "     });"
    "   })"
    " });"
    "</script>"
    "</table>";
}

std::string Auth::get_success_page() const {
    return "<div id='bodyInner' class='blue'>" + NAVBAR + \
        "<div class=\"container center-block\">"
        "<h1 class=\"text-center\">Successfully authenticated</h1>"
        "</div></div>";
}

std::string Auth::get_error_page(const std::string& error) const {
    std::string error_page = "<div id='bodyInner' class='blue'>" + NAVBAR;
    error_page += "<div class=\"container center-block\">"
            "<h1 class=\"text-center\">An error occurred</h1>";
    if (!error.empty())
        error_page += "<h2 class=\"text-center\">" + error + "</h2>";
    error_page += "</div></div>";
    return error_page;
}

const std::string& Auth::authorization_code() const {
  return authorization_code_;
}

void Auth::set_authorization_code(const std::string& code) {
  authorization_code_ = code;
}

const std::string& Auth::client_id() const { return client_id_; }

void Auth::set_client_id(const std::string& client_id) {
  client_id_ = client_id;
}

const std::string& Auth::client_secret() const { return client_secret_; }

void Auth::set_client_secret(const std::string& client_secret) {
  client_secret_ = client_secret;
}

std::string Auth::redirect_uri() const {
  return "http://localhost:" + std::to_string(redirect_uri_port()) +
          redirect_uri_prefix_;
}

uint16_t Auth::redirect_uri_port() const { return redirect_uri_port_; }

void Auth::set_redirect_uri_port(uint16_t port) { redirect_uri_port_ = port; }

std::string Auth::redirect_uri_prefix() const { return redirect_uri_prefix_; }

void Auth::set_redirect_uri_prefix(const std::string& prefix) {
    redirect_uri_prefix_ = prefix;
}

Auth::Token* Auth::access_token() const { return access_token_.get(); }

void Auth::set_access_token(Token::Pointer token) {
  access_token_ = std::move(token);
}

IHttp* Auth::http() const { return http_; }

IHttpd* Auth::httpd() const { return httpd_; }

std::string Auth::awaitAuthorizationCode(
    std::string code_parameter_name, std::string error_parameter_name,
    std::function<void()> server_started,
    std::function<void()> server_stopped) const {
  uint16_t http_server_port = redirect_uri_port();
  Semaphore semaphore;
  HttpServerData data = {this,
                         "",
                         code_parameter_name,
                         error_parameter_name,
                         http_server_port,
                         HttpServerData::Awaiting,
                         &semaphore};
  httpd_->startServer(http_server_port, requestCallback, &data);
  if (server_started) server_started();
  semaphore.wait();
  httpd_->stopServer();
  if (server_stopped) server_stopped();
  if (data.state_ == HttpServerData::Accepted)
    return data.code_;
  else
    return "";
}

std::string Auth::requestAuthorizationCode(
    std::function<void()> server_started,
    std::function<void()> server_stopped) const {
  return awaitAuthorizationCode("code", "error", server_started,
                                server_stopped);
}

IAuth::Token::Pointer Auth::fromTokenString(
    const std::string& refresh_token) const {
  Token::Pointer token = util::make_unique<Token>();
  token->refresh_token_ = refresh_token;
  token->expires_in_ = -1;
  return token;
}

}  // namespace cloudstorage
