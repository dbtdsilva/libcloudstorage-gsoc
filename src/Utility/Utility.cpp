/*****************************************************************************
 * Utility.cpp
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

#include "Utility.h"

#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <json/json.h>

namespace cloudstorage {

namespace util {

std::string remove_whitespace(const std::string& str) {
  std::string result;
  for (char c : str)
    if (!isspace(c)) result += c;
  return result;
}

range parse_range(const std::string& r) {
  std::string str = remove_whitespace(r);
  int l = strlen("bytes=");
  if (str.substr(0, l) != "bytes=") return {-1, -1};
  std::string n1, n2;
  int it = l;
  while (it < r.length() && str[it] != '-') n1 += str[it++];
  it++;
  while (it < r.length()) n2 += str[it++];
  auto begin = n1.empty() ? -1 : atoll(n1.c_str());
  auto end = n2.empty() ? -1 : atoll(n2.c_str());
  return {begin, end == -1 ? -1 : (end - begin + 1)};
}

std::string Url::unescape(const std::string& value) {
    std::ostringstream unescaped;
    int hex_extract;
    for (int i = 0; i < value.length(); i++) {
        if (value[i] == '%') {
            // Failed to unescape (there is not enough digits with the %
            if (i >= value.length() - 2)
                return "";
            sscanf(value.substr(i + 1, 2).c_str(), "%x", &hex_extract);
            unescaped << hex_extract;
            i += 2; // Skip the two elements that were read
        } else {
            unescaped << value[i];
        }
    }

    return unescaped.str();
}

std::string Url::escape(const std::string& value) {
    std::ostringstream escaped;

    escaped << std::setfill('0');
    escaped << std::hex;

    for (std::string::const_iterator i = value.begin(); i != value.end(); i++) {
        std::string::value_type c = *i;
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char) c);
        escaped << std::nouppercase;
    }

    return escaped.str();
}

std::string Url::escapeHeader(const std::string& header) {
    return Json::valueToQuotedString(header.c_str());
}
} // namespace util
} // namespace cloudstorage
