/*****************************************************************************
 * IHttpd : IHttpd interface
 *
 *****************************************************************************
 * Copyright (C) 2017 VideoLAN
 *
 * Authors: Diogo Silva <dbtdsilva@gmail.com>
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

#ifndef IHTTPD_H
#define IHTTPD_H

#include <memory>
#include <functional>
#include <map>
#include <string>

namespace cloudstorage {

class IHttpd {
public:
    using Pointer = std::unique_ptr<IHttpd>;
    struct RequestData {
        using Pointer = std::unique_ptr<RequestData>;
        
        std::string url;
        std::map<std::string, std::string> args;
        std::map<std::string, std::string> headers;
    };
    
    virtual void startServer(
        uint16_t port, 
        std::function<void(RequestData::Pointer, void*)> request_callback,
        void* data) = 0;
    virtual void stopServer() = 0;
    virtual std::string getArgument(const std::string& arg_name) const = 0;
    virtual void sendResponse(const std::string& response) = 0;
};

} // namespace cloudstorage

#endif  // IHTTPD_H
