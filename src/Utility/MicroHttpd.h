/*****************************************************************************
 * MicroHttpd.h : interface of MicroHttpd
 *
 *****************************************************************************
 * Copyright (C) 2017-2017 VideoLAN
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

#ifndef MICROHTTPD_H
#define MICROHTTPD_H

#include "IHttpd.h"
#include <microhttpd.h>

namespace cloudstorage {

class MicroHttpd : public IHttpd {
public:
    void startServer(uint16_t port, CallbackFunction request_callback, 
            void* data) override;
    void stopServer() override;
private:
    static int MHDRequestCallback(void*, MHD_Connection*, const char*, 
            const char*, const char*, const char*, size_t*, void**);
    MHD_Daemon* http_server;
    
    struct CallbackData {
        CallbackFunction request_callback;
        void* custom_data;
    } callback_data;
};

}

#endif /* MICROHTTPD_H */

