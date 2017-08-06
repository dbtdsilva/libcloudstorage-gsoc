/*****************************************************************************
 * YouTube.cpp : YouTube implementation
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

#include "YouTube.h"

#include <json/json.h>
#include <cstring>

#include "Request/DownloadFileRequest.h"
#include "Request/ListDirectoryRequest.h"
#include "Request/Request.h"

#include "Utility/Item.h"
#include "Utility/Utility.h"

const std::string VIDEO_ID_PREFIX = "video###";
const std::string AUDIO_ID_PREFIX = "audio###";
const std::string AUDIO_DIRECTORY = "audio";

using namespace std::placeholders;

namespace cloudstorage {

YouTube::YouTube()
    : CloudProvider(util::make_unique<Auth>()),
      youtube_dl_url_("http://youtube-dl.appspot.com") {}

void YouTube::initialize(InitData&& data) {
  setWithHint(data.hints_, "youtube_dl_url",
              [this](std::string url) { youtube_dl_url_ = url; });
  CloudProvider::initialize(std::move(data));
}

ICloudProvider::Hints YouTube::hints() const {
  Hints result = {{"youtube_dl_url", youtube_dl_url_}};
  auto t = CloudProvider::hints();
  result.insert(t.begin(), t.end());
  return result;
}

std::string YouTube::name() const { return "youtube"; }

std::string YouTube::endpoint() const { return "https://www.googleapis.com"; }

ICloudProvider::ListDirectoryRequest::Pointer YouTube::listDirectoryAsync(
    IItem::Pointer item, IListDirectoryCallback::Pointer callback) {
  return std::make_shared<cloudstorage::ListDirectoryRequest>(
             shared_from_this(), std::move(item), std::move(callback), true)
      ->run();
}

ICloudProvider::GetItemDataRequest::Pointer YouTube::getItemDataAsync(
    const std::string& id, GetItemDataCallback callback) {
  auto r = std::make_shared<Request<EitherError<IItem>>>(shared_from_this());
  r->set([=](Request<EitherError<IItem>>::Ptr r) {
    if (id == AUDIO_DIRECTORY) {
      IItem::Pointer i = std::make_shared<Item>(
          AUDIO_DIRECTORY, AUDIO_DIRECTORY, IItem::FileType::Directory);
      callback(i);
      return r->done(i);
    }
    auto response_stream = std::make_shared<std::stringstream>();
    r->sendRequest(
        [=](util::Output input) { return getItemDataRequest(id, *input); },
        [=](EitherError<util::Output> e) {
          if (e.left()) {
            callback(e.left());
            return r->done(e.left());
          }
          auto i = getItemDataResponse(
              *response_stream, id.find(AUDIO_ID_PREFIX) != std::string::npos);
          auto stream = std::make_shared<std::stringstream>();
          if (i->type() == IItem::FileType::Audio) {
            r->sendRequest(
                [=](util::Output) {
                  auto request =
                      http()->create(youtube_dl_url_ + "/api/info", "GET");
                  request->setParameter("format", "bestaudio");
                  request->setParameter(
                      "url",
                      "http://youtube.com/watch?v=" +
                          extractId(id).substr(VIDEO_ID_PREFIX.length()));
                  return request;
                },
                [=](EitherError<util::Output> e) {
                  if (e.left()) {
                    callback(e.left());
                    return r->done(e.left());
                  }
                  Json::Value response;
                  *stream >> response;
                  auto item = i;
                  for (auto v : response["info"]["formats"])
                    if (v["format_id"] == response["info"]["format_id"]) {
                      auto nitem = std::make_shared<Item>(
                          i->filename() + "." + v["ext"].asString(), i->id(),
                          i->type());
                      nitem->set_url(v["url"].asString());
                      item = nitem;
                    }
                  callback(item);
                  r->done(item);
                },
                stream);
          } else {
            callback(i);
            r->done(i);
          }
        },
        response_stream);
  });
  return r->run();
}

ICloudProvider::DownloadFileRequest::Pointer YouTube::downloadFileAsync(
    IItem::Pointer item, IDownloadFileCallback::Pointer callback) {
  auto r = std::make_shared<Request<EitherError<void>>>(shared_from_this());
  r->set([=](Request<EitherError<void>>::Ptr r) {
    std::string url = item->url();
    auto download = [=](std::string url) {
      auto wrapper = std::make_shared<DownloadStreamWrapper>(std::bind(
          &IDownloadFileCallback::receivedData, callback.get(), _1, _2));
      auto stream = std::make_shared<std::ostream>(wrapper.get());
      r->sendRequest([=](util::Output) { return http()->create(url, "GET"); },
                     [=](EitherError<util::Output> e) {
                       wrapper;
                       if (e.left()) {
                         callback->done(e.left());
                         r->done(e.left());
                       } else {
                         callback->done(nullptr);
                         r->done(nullptr);
                       }
                     },
                     stream, std::bind(&IDownloadFileCallback::progress,
                                       callback.get(), _1, _2));
    };
    if (item->type() == IItem::FileType::Audio) {
      r->subrequest(getItemDataAsync(item->id(), [=](EitherError<IItem> e) {
        if (e.left()) {
          callback->done(e.left());
          r->done(e.left());
        } else {
          download(e.right()->url());
        }
      }));
    } else {
      download(item->url());
    }
  });
  return r->run();
}

IHttpRequest::Pointer YouTube::getItemDataRequest(const std::string& full_id,
                                                  std::ostream&) const {
  std::string id = extractId(full_id);
  if (id.find(VIDEO_ID_PREFIX) != std::string::npos) {
    auto request = http()->create(endpoint() + "/youtube/v3/videos", "GET");
    request->setParameter("part", "contentDetails,snippet");
    request->setParameter("id", id.substr(VIDEO_ID_PREFIX.length()));
    return request;
  } else {
    auto request = http()->create(endpoint() + "/youtube/v3/playlists", "GET");
    request->setParameter("part", "contentDetails,snippet");
    request->setParameter("id", id);
    return request;
  }
}

IHttpRequest::Pointer YouTube::listDirectoryRequest(
    const IItem& item, const std::string& page_token, std::ostream&) const {
  if (item.id() == rootDirectory()->id() || item.id() == AUDIO_DIRECTORY) {
    if (page_token.empty())
      return http()->create(
          endpoint() +
              "/youtube/v3/"
              "channels?mine=true&part=contentDetails,snippet",
          "GET");
    else if (page_token == "real_playlist")
      return http()->create(
          endpoint() +
              "/youtube/v3/"
              "playlists?mine=true&maxResults=50&part=snippet",
          "GET");
    else
      return http()->create(
          endpoint() +
              "/youtube/v3/"
              "playlists?mine=true&maxResults=50&part=snippet&pageToken=" +
              page_token,
          "GET");
  } else {
    auto request =
        http()->create(endpoint() + "/youtube/v3/playlistItems", "GET");
    request->setParameter("part", "snippet");
    request->setParameter("maxResults", "50");
    request->setParameter("playlistId", extractId(item.id()));
    if (!page_token.empty()) request->setParameter("pageToken", page_token);
    return request;
  }
}

IItem::Pointer YouTube::getItemDataResponse(std::istream& stream,
                                            bool audio) const {
  Json::Value response;
  stream >> response;
  return toItem(response["items"][0], response["kind"].asString(), audio);
}

std::vector<IItem::Pointer> YouTube::listDirectoryResponse(
    const IItem& directory, std::istream& stream,
    std::string& next_page_token) const {
  Json::Value response;
  Json::Reader().parse(static_cast<const std::stringstream&>(std::stringstream()
                                                             << stream.rdbuf())
                           .str(),
                       response);
  std::vector<IItem::Pointer> result;
  std::string id_prefix =
      directory.id().find(AUDIO_ID_PREFIX) != std::string::npos ||
              directory.id() == AUDIO_DIRECTORY
          ? AUDIO_ID_PREFIX
          : "";
  std::string name_prefix = id_prefix.empty() ? "" : AUDIO_DIRECTORY + " ";
  if (response["kind"].asString() == "youtube#channelListResponse") {
    Json::Value related_playlists =
        response["items"][0]["contentDetails"]["relatedPlaylists"];
    for (const std::string& name : related_playlists.getMemberNames()) {
      auto item = util::make_unique<Item>(
          name_prefix + name, id_prefix + related_playlists[name].asString(),
          IItem::FileType::Directory);
      item->set_thumbnail_url(
          response["items"][0]["snippet"]["thumbnails"]["default"]["url"]
              .asString());
      result.push_back(std::move(item));
    }
    next_page_token = "real_playlist";
  } else {
    for (const Json::Value& v : response["items"])
      result.push_back(
          toItem(v, response["kind"].asString(), !id_prefix.empty()));
  }
  if (response.isMember("nextPageToken"))
    next_page_token = response["nextPageToken"].asString();
  else if (directory.id() == rootDirectory()->id() && next_page_token.empty())
    result.push_back(util::make_unique<Item>(AUDIO_DIRECTORY, AUDIO_DIRECTORY,
                                             IItem::FileType::Directory));
  return result;
}

IItem::Pointer YouTube::toItem(const Json::Value& v, std::string kind,
                               bool audio) const {
  std::string id_prefix = audio ? AUDIO_ID_PREFIX : "";
  std::string name_prefix = audio ? AUDIO_DIRECTORY + " " : "";
  if (kind == "youtube#playlistListResponse") {
    auto item = util::make_unique<Item>(
        name_prefix + v["snippet"]["title"].asString(),
        id_prefix + v["id"].asString(), IItem::FileType::Directory);
    item->set_thumbnail_url(
        v["snippet"]["thumbnails"]["default"]["url"].asString());
    return std::move(item);
  } else {
    std::string video_id;
    if (kind == "youtube#playlistItemListResponse")
      video_id = v["snippet"]["resourceId"]["videoId"].asString();
    else if (kind == "youtube#videoListResponse")
      video_id = v["id"].asString();
    else
      return nullptr;
    auto item = util::make_unique<Item>(
        v["snippet"]["title"].asString() + (audio ? ".webm" : ".mp4"),
        id_prefix + VIDEO_ID_PREFIX + video_id,
        audio ? IItem::FileType::Audio : IItem::FileType::Video);
    item->set_thumbnail_url(
        v["snippet"]["thumbnails"]["default"]["url"].asString());
    item->set_url(youtube_dl_url_ +
                  "/api/play?url=https://www.youtube.com/"
                  "watch?v=" +
                  video_id);
    return std::move(item);
  }
}

std::string YouTube::extractId(const std::string& full_id) const {
  if (full_id.find(AUDIO_ID_PREFIX) != std::string::npos)
    return full_id.substr(AUDIO_ID_PREFIX.length());
  else
    return full_id;
}

std::string YouTube::Auth::authorizeLibraryUrl() const {
  return "https://accounts.google.com/o/oauth2/auth?client_id=" + client_id() +
         "&redirect_uri=" + redirect_uri() +
         "&scope=https://www.googleapis.com/auth/youtube"
         "&response_type=code&access_type=offline&prompt=consent"
         "&state=" +
         state();
}

}  // namespace cloudstorage
