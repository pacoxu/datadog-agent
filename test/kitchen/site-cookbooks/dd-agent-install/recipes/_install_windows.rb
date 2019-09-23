#
# Cookbook Name:: dd-agent-install
# Recipe:: _install_windows
#
# Copyright (C) 2019 Datadog
#
# All rights reserved - Do Not Redistribute
#

include_recipe 'dd-agent-install::_install_windows_base'

agent_config_file = ::File.join(node['dd-agent-install']['config_dir'], 'datadog.conf')

# Set the Agent service enable or disable
agent_enable = node['dd-agent-install']['agent_enable'] ? :enable : :disable
# Set the correct Agent startup action
agent_start = node['dd-agent-install']['agent_start'] ? :start : :stop


include_recipe 'dd-agent-install::_agent6_windows_config'

# Common configuration
service 'datadog-agent' do
  service_name node['dd-agent-install']['agent_name']
  action [agent_enable, agent_start]
  supports :restart => true, :start => true, :stop => true
  subscribes :restart, "template[#{agent_config_file}]", :immediate unless node['dd-agent-install']['agent_start'] == false
  restart_command "powershell -Command \"restart-service -Force -Name datadogagent\""
  # HACK: the restart can fail when we hit systemd's restart limits (by default, 5 starts every 10 seconds)
  # To workaround this, retry once after 5 seconds, and a second time after 10 seconds
  retries 2
  retry_delay 5
end
