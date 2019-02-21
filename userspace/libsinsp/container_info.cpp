/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

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

#include <utility>

#include "container_info.h"
#include "sinsp.h"
#include "sinsp_int.h"

sinsp_container_info::container_health_probe::container_health_probe()
{
}

sinsp_container_info::container_health_probe::container_health_probe(const container_health_probe &other)
	: m_probe_type(other.m_probe_type),
	  m_health_probe_exe(other.m_health_probe_exe),
	  m_health_probe_args(other.m_health_probe_args),
	  m_obj(other.m_obj)
{
}

sinsp_container_info::container_health_probe::container_health_probe(container_health_probe &&other)
	: m_probe_type(other.m_probe_type),
	  m_health_probe_exe(std::move(other.m_health_probe_exe)),
	  m_health_probe_args(std::move(other.m_health_probe_args)),
	  m_obj(std::move(other.m_obj))
{
}

sinsp_container_info::container_health_probe::~container_health_probe()
{
}

sinsp_container_info::container_health_probe &sinsp_container_info::container_health_probe::operator=(const container_health_probe &other)
{
	m_probe_type = other.m_probe_type;
	m_health_probe_exe = other.m_health_probe_exe;
	m_health_probe_args = other.m_health_probe_args;
	m_obj = other.m_obj;

	return *this;
}

void sinsp_container_info::container_health_probe::add_health_probes(const Json::Value &config_obj,
								     std::list<container_health_probe> &probes)
{
	Json::Value spec;
	bool liveness_readiness_added = false;

	// When parsing the full container json for live containers, a label contains stringified json that
	// contains the probes.
	if (container_health_probe::get_k8s_pod_spec(config_obj, spec))
	{
		if(spec.isMember("livenessProbe"))
		{
			container_health_probe probe;
			if(probe.parse_liveness_readiness_probe(spec["livenessProbe"], PT_LIVENESS_PROBE))
			{
				probes.push_back(probe);
				liveness_readiness_added = true;
			}
		}
		else if(spec.isMember("readinessProbe"))
		{
			container_health_probe probe;
			if(probe.parse_liveness_readiness_probe(spec["readinessProbe"], PT_READINESS_PROBE))
			{
				probes.push_back(probe);
				liveness_readiness_added = true;
			}
		}
	}

	// When parsing the json for container_json events,
	// the livenessProbe/readinessProbe are directly
	// available.
	if (config_obj.isMember("livenessProbe"))
	{
		container_health_probe probe;
		if(probe.parse_liveness_readiness_probe(config_obj["livenessProbe"], PT_LIVENESS_PROBE))
		{
			probes.push_back(probe);
			liveness_readiness_added = true;
		}
	}

	if (config_obj.isMember("readinessProbe"))
	{
		container_health_probe probe;
		if(probe.parse_liveness_readiness_probe(config_obj["readinessProbe"], PT_READINESS_PROBE))
		{
			probes.push_back(probe);
			liveness_readiness_added = true;
		}
	}

	// To avoid any confusion about containers that both refer to
	// a healthcheck and liveness/readiness probe, we only
	// consider a healthcheck if no liveness/readiness was added.

	if(!liveness_readiness_added && config_obj.isMember("Healthcheck"))
	{
		container_health_probe probe;
		if(probe.parse_healthcheck(config_obj["Healthcheck"]))
		{
			probes.push_back(probe);
		}
	}
}

void sinsp_container_info::container_health_probe::add_to_json(Json::Value &container_obj) const
{
	switch(m_probe_type)
	{
	case PT_HEALTHCHECK:
		container_obj["Healthcheck"] = m_obj;
		break;
	case PT_LIVENESS_PROBE:
		container_obj["livenessProbe"] = m_obj;
		break;
	case PT_READINESS_PROBE:
		container_obj["readinessProbe"] = m_obj;
		break;
	default:
		g_logger.format(sinsp_logger::SEV_ERROR, "Unknown health probe type %d",
				m_probe_type);
	}
}

bool sinsp_container_info::container_health_probe::get_k8s_pod_spec(const Json::Value &config_obj, Json::Value &spec)
{
	std::string cfg_str;
	Json::Reader reader;
	std::string k8s_label = "annotation.kubectl.kubernetes.io/last-applied-configuration";

	if(config_obj.isNull() ||
	   !config_obj.isMember("Labels") ||
	   !config_obj["Labels"].isMember(k8s_label))
	{
		return false;
	}

	// The pod spec is stored as a stringified json label on the container
	cfg_str = config_obj["Labels"][k8s_label].asString();

	if(cfg_str == "")
	{
		return false;
	}

	Json::Value cfg;
	if(!reader.parse(cfg_str.c_str(), cfg))
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Could not parse pod config '%s'", cfg_str.c_str());
		return false;
	}

	if(!cfg.isMember("spec") ||
	   !cfg["spec"].isMember("containers") ||
	   !cfg["spec"]["containers"].isArray())
	{
		return false;
	}

	spec = cfg["spec"]["containers"][0];

	return true;
}

bool sinsp_container_info::container_health_probe::parse_healthcheck(const Json::Value &healthcheck_obj)
{
	if(healthcheck_obj.isNull() ||
	   !healthcheck_obj.isMember("Test"))
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Could not parse health check from %s",
				Json::FastWriter().write(healthcheck_obj).c_str());

		return false;
	}

	const Json::Value &test_obj = healthcheck_obj["Test"];

	if(!test_obj.isArray() || test_obj.size() < 2)
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Could not parse health check from %s",
				Json::FastWriter().write(healthcheck_obj).c_str());
		return false;
	}

	if(test_obj[0].asString() == "CMD")
	{
		m_health_probe_exe = normalize_arg(test_obj[1].asString());

		for(uint32_t i = 2; i < test_obj.size(); i++)
		{
			m_health_probe_args.push_back(normalize_arg(test_obj[i].asString()));
		}
	}
	else if(test_obj[0].asString() == "CMD-SHELL")
	{
		m_health_probe_exe = "/bin/sh";
		m_health_probe_args.push_back("-c");
		m_health_probe_args.push_back(test_obj[1].asString());
	}
	else
	{
		// This occurs when HEALTHCHECK is NONE. No warning log in this case.
		return false;
	}

	m_obj = healthcheck_obj;
	m_probe_type = PT_HEALTHCHECK;
	return true;
}

bool sinsp_container_info::container_health_probe::parse_liveness_readiness_probe(const Json::Value &probe_obj, probe_type ptype)
{
	if(probe_obj.isNull() ||
	   !probe_obj.isMember("exec") ||
	   !probe_obj["exec"].isMember("command"))
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Could not parse liveness/readiness probe from %s",
				Json::FastWriter().write(probe_obj).c_str());
		return false;
	}

	const Json::Value command_obj = probe_obj["exec"]["command"];

	if(!command_obj.isNull() && command_obj.isArray())
	{
		m_health_probe_exe = normalize_arg(command_obj[0].asString());
		for(uint32_t i = 1; i < command_obj.size(); i++)
		{
			m_health_probe_args.push_back(normalize_arg(command_obj[i].asString()));
		}
	}

	m_obj = probe_obj;
	m_probe_type = ptype;
	return true;
}

std::string sinsp_container_info::container_health_probe::normalize_arg(const std::string &arg)
{
	std::string ret = arg;

	if(ret.empty())
	{
		return ret;
	}

	// Remove pairs of leading/trailing " or ' chars, if present
	while(ret.front() == '"' || ret.front() == '\'')
	{
		if(ret.back() == ret.front())
		{
			ret.pop_back();
			ret.erase(0, 1);
		}
	}

	return ret;
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_idx(uint32_t idx) const
{
	if (idx >= m_mounts.size())
	{
		return NULL;
	}

	return &(m_mounts[idx]);
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_source(std::string &source) const
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(source.c_str(), mntinfo.m_source.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_dest(std::string &dest) const
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(dest.c_str(), mntinfo.m_dest.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

sinsp_container_info::container_health_probe::probe_type sinsp_container_info::match_health_probe(sinsp_threadinfo *tinfo)
{
	auto pred = [&] (container_health_probe &p) {
                return (p.m_health_probe_exe == tinfo->m_exe &&
			p.m_health_probe_args == tinfo->m_args);
        };

	auto match = std::find_if(m_health_probes.begin(),
				  m_health_probes.end(),
				  pred);

	if(match == m_health_probes.end())
	{
		return container_health_probe::PT_NONE;
	}

	return match->m_probe_type;
}


