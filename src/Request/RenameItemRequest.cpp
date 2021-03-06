/*****************************************************************************
 * RenameItemRequest.cpp : RenameItemRequest implementation
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

#include "RenameItemRequest.h"

#include "CloudProvider/CloudProvider.h"

namespace cloudstorage {

RenameItemRequest::RenameItemRequest(std::shared_ptr<CloudProvider> p,
                                     IItem::Pointer item,
                                     const std::string& name,
                                     RenameItemCallback callback)
    : Request(p) {
  set([=](Request::Pointer request) {
    auto output = std::make_shared<std::stringstream>();
    sendRequest(
        [=](util::Output stream) {
          return p->renameItemRequest(*item, name, *stream);
        },
        [=](EitherError<util::Output> e) {
          if (e.left()) {
            callback(e.left());
            request->done(e.left());
          } else {
            callback(nullptr);
            request->done(nullptr);
          }
        },
        output);
  });
}

RenameItemRequest::~RenameItemRequest() { cancel(); }

}  // namespace cloudstorage
