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
    // Public structure definitions
    typedef std::map<std::string, std::string> ConnectionValues;
    struct RequestData {
        std::string url;
        ConnectionValues args;
        ConnectionValues headers;
        void *internal_data;
        void *custom_data;
    };
    typedef std::function<int(IHttpd::RequestData*)> CallbackFunction;
    
    // Public functions
    /**
     * Initiates a HTTPD server with the given values and each request will
     * be redirected to the callback.
     *
     * @param port integer value containing the server port
     * @param request_callback callback that receives every request
     * @param data callback parameters
     */
    virtual void startServer(uint16_t port, 
        CallbackFunction request_callback, void* data) = 0;
    
    /**
     * This functions allows to stop an already started daemon.
     */
    virtual void stopServer() = 0;
    
    /**
     * Searches for a specific argument in the given request.
     *
     * @param data This value should be passed from the requests callback
     * @param arg_name The argument being searched
     * @return Returns the value of the argument or empty if not found
     */
    static std::string getArgument(RequestData* data, const std::string& arg_name)
    {
        auto it = data->args.find(arg_name);
        return it == data->args.end() ? "" : it->second;
    }
    
    /**
     * Searches for a specific header in the given request.
     *
     * @param data This value should be passed from the requests callback
     * @param header_name The header name being searched
     * @return Returns the value of the header or empty if not found
     */
    static std::string getHeader(RequestData* data, const std::string& header_name)
    {
        auto it = data->args.find(header_name);
        return it == data->args.end() ? "" : it->second;
    }
    
    /**
     * This functions allows to send a response for a given request
     *
     * @param data This value should be passed from the requests callback
     * @param response Contains the HTML code for the response
     * @return Returns 0 if response was successfully and negative values when
     *  an error has occured.
     */
    virtual int sendResponse(RequestData* data, const std::string& response) = 0;
};



} // namespace cloudstorage

#endif  // IHTTPD_H
