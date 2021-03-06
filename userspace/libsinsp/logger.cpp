/*
Copyright (C) 2013-2019 Sysdig, Inc.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
#include "logger.h"
#include "sinsp.h"
#include "sinsp_int.h"

#ifndef _WIN32
#include <sys/time.h>
#else
#include <time.h>
#endif
#include <stdarg.h>

namespace
{

thread_local char s_tbuf[16384];

} // end namespace

const uint32_t sinsp_logger::OT_NONE     = 0;
const uint32_t sinsp_logger::OT_STDOUT   = 1;
const uint32_t sinsp_logger::OT_STDERR   = (OT_STDOUT   << 1);
const uint32_t sinsp_logger::OT_FILE     = (OT_STDERR   << 1);
const uint32_t sinsp_logger::OT_CALLBACK = (OT_FILE     << 1);
const uint32_t sinsp_logger::OT_NOTS     = (OT_CALLBACK << 1);

sinsp_logger::sinsp_logger():
	m_file(nullptr),
	m_callback(nullptr),
	m_flags(OT_NONE),
	m_sev(SEV_INFO)
{ }

sinsp_logger::~sinsp_logger()
{
	if(m_file)
	{
		ASSERT(m_flags & sinsp_logger::OT_FILE);
		fclose(m_file);
	}
}

bool sinsp_logger::is_callback() const
{
	 return (m_flags & sinsp_logger::OT_CALLBACK) != 0;
}

bool sinsp_logger::is_event_severity(const severity sev)
{
	 return (static_cast<int>(sev) >= static_cast<int>(SEV_EVT_MIN) &&
			static_cast<int>(sev) <= static_cast<int>(SEV_EVT_MAX));
}

uint32_t sinsp_logger::get_log_output_type() const
{
	return m_flags;
}

void sinsp_logger::add_stdout_log()
{
	m_flags |= sinsp_logger::OT_STDOUT;
}

void sinsp_logger::add_stderr_log()
{
	m_flags |= sinsp_logger::OT_STDERR;
}

void sinsp_logger::add_file_log(const std::string& filename)
{
	ASSERT(m_file == nullptr);

	m_file = fopen(filename.c_str(), "w");
	if(!m_file)
	{
		throw sinsp_exception("Unable to open file " + filename + " for writing");
	}

	m_flags |= sinsp_logger::OT_FILE;
}

void sinsp_logger::disable_timestamps()
{
	m_flags |= sinsp_logger::OT_NOTS;
}

void sinsp_logger::add_callback_log(const sinsp_logger_callback callback)
{
	const sinsp_logger_callback old_cb = m_callback.exchange(callback);

	ASSERT(old_cb == nullptr);

	// For release builds, the compiler doesn't see that old_cb is used,
	// so do something that will satisfy the compiler
	static_cast<void>(old_cb);

	m_flags |= sinsp_logger::OT_CALLBACK;
}

void sinsp_logger::remove_callback_log()
{
	m_callback = nullptr;
	m_flags &= ~sinsp_logger::OT_CALLBACK;
}

void sinsp_logger::set_severity(const severity sev)
{
	if(m_sev < SEV_MIN || m_sev > SEV_MAX)
	{
		throw sinsp_exception("Invalid log severity");
	}

	m_sev = sev;
}

sinsp_logger::severity sinsp_logger::get_severity() const
{
	return m_sev;
}

void sinsp_logger::log(std::string msg, const event_severity sev)
{
	sinsp_logger_callback cb = nullptr;

	if(is_callback())
	{
		cb = m_callback;
	}

	if(cb != nullptr)
	{
		cb(std::move(msg), static_cast<uint32_t>(sev));
	}
}

void sinsp_logger::log(std::string msg, const severity sev)
{
	sinsp_logger_callback cb = nullptr;

	if((sev > m_sev) || is_event_severity(sev))
	{
		return;
	}

	if((m_flags & sinsp_logger::OT_NOTS) == 0)
	{
		struct timeval ts = {};

		if(gettimeofday(&ts, nullptr) == 0)
		{
			const std::string::size_type ts_length = 22;
			char ts_buf[ts_length + 1];
			struct tm time_info = {};

			gmtime_r(&ts.tv_sec, &time_info);

			//
			// This formatted string is ts_length bytes long:
			//
			//           1         2
			// "1234567890123456789012
			// "xx-xx xx:xx:xx.xxxxxx "
			//
			snprintf(ts_buf,
				 sizeof(ts_buf),
				 "%.2d-%.2d %.2d:%.2d:%.2d.%.6d ",
				 time_info.tm_mon + 1,
				 time_info.tm_mday,
				 time_info.tm_hour,
				 time_info.tm_min,
				 time_info.tm_sec,
				 (int)ts.tv_usec);

			ts_buf[sizeof(ts_buf) - 1] = '\0';
			msg.insert(0, ts_buf, ts_length);
		}
	}

	if(is_callback())
	{
		cb = m_callback;
	}

	if(cb != nullptr)
	{
		cb(std::move(msg), static_cast<uint32_t>(sev));
	}
	else if((m_flags & sinsp_logger::OT_FILE) && m_file)
	{
		fprintf(m_file, "%s\n", msg.c_str());
		fflush(m_file);
	}
	else if(m_flags & sinsp_logger::OT_STDOUT)
	{
		fprintf(stdout, "%s\n", msg.c_str());
		fflush(stdout);
	}
	else if(m_flags & sinsp_logger::OT_STDERR)
	{
		fprintf(stderr, "%s\n", msg.c_str());
		fflush(stderr);
	}
}

const char* sinsp_logger::format(const severity sev, const char* const fmt, ...)
{
	if(!is_callback() && is_event_severity(sev))
	{
		s_tbuf[0] = '\0';
		return s_tbuf;
	}

	va_list ap;

	va_start(ap, fmt);
	vsnprintf(s_tbuf, sizeof(s_tbuf), fmt, ap);
	va_end(ap);

	log(s_tbuf, sev);

	return s_tbuf;
}

const char* sinsp_logger::format(const char* const fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(s_tbuf, sizeof(s_tbuf), fmt, ap);
	va_end(ap);

	log(s_tbuf, SEV_INFO);

	return s_tbuf;
}
