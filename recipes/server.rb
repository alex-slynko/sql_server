#
# Author:: Seth Chisamore (<schisamo@opscode.com>)
# Cookbook Name:: sql_server
# Recipe:: server
#
# Copyright:: 2011, Opscode, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

::Chef::Recipe.send(:include, Opscode::OpenSSL::Password)

service_name = node['sql_server']['instance_name']
if node['sql_server']['instance_name'] == 'SQLEXPRESS'
  service_name = "MSSQL$#{node['sql_server']['instance_name']}"
end
  
static_tcp_reg_key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\\' + node['sql_server']['reg_version'] +
  node['sql_server']['instance_name'] + '\MSSQLServer\SuperSocketNetLib\Tcp\IPAll'

# generate and set a password for the 'sa' super user
node.set_unless['sql_server']['server_sa_password'] = "#{secure_password}-aA12"
# force a save so we don't lose our generated password on a failed chef run
node.save unless Chef::Config[:solo]

config_file_path = win_friendly_path(File.join(Chef::Config[:file_cache_path], "ConfigurationFile.ini"))

template config_file_path do
  source "ConfigurationFile.ini.erb"
end

if  mssql_username = node['sql_server']['installer_runas_username'] && mssql_password = node['sql_server']['installer_runas_password']
  if not (registry_key_exists?('HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL') &&
          registry_value_exists?(
            'HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL',
            { :name => "#{service_name}", :type => :string, :data => "MSSQL10_50.MSSQLSERVER" }))


    # Install working around MS SQL Server installer 'runas' requirements
    powershell "Install MSSQL" do
      action :run
      code <<-EOH
function ps-runas ([String] $cmd, [String] $arguments)
{
  Write-Host "ps-runas cmd: $cmd"
  Write-Host "ps-runas args: $arguments"

  $secpasswd = ConvertTo-SecureString "#{mssql_password}" -AsPlainText -Force

  $process = New-Object System.Diagnostics.Process
  $setup = $process.StartInfo
  $setup.FileName = $cmd
  $setup.Arguments = $arguments
  $setup.UserName = "#{mssql_username}"
  $setup.Password = $secpasswd
  $setup.Verb = "runas"
  $setup.UseShellExecute = $false
  $setup.RedirectStandardError = $true
  $setup.RedirectStandardOutput = $true
  $setup.RedirectStandardInput = $false

  # Hook into the standard output and error stream events
  $errEvent = Register-ObjectEvent -InputObj $process `
    -Event "ErrorDataReceived" `
    -Action `
    {
        param
        (
            [System.Object] $sender,
            [System.Diagnostics.DataReceivedEventArgs] $e
        )
        Write-Host $e.Data
    }
  $outEvent = Register-ObjectEvent -InputObj $process `
    -Event "OutputDataReceived" `
    -Action `
    {
        param
        (
            [System.Object] $sender,
            [System.Diagnostics.DataReceivedEventArgs] $e
        )
        Write-Host $e.Data
    }

  Write-Host "ps-runas starting: $cmd"

  if (!$process.Start())
  {
    Write-Error "Failed to start $cmd"
  }

  $process.BeginOutputReadLine()
  $process.BeginErrorReadLine()

  # Wait until process exit
  $process.WaitForExit()

  $process.CancelOutputRead()
  $process.CancelErrorRead()
  $process.Close()
}
ps-runas "#{node['sql_server']['server']['url']}" "/q /ConfigurationFile=#{config_file_path}"
      EOH
    end
  else
    windows_package node['sql_server']['server']['package_name'] do
      source node['sql_server']['server']['url']
      checksum node['sql_server']['server']['checksum']
      installer_type :custom
      options "/q /ConfigurationFile=#{config_file_path}"
      options "#{node['sql_server']['installer_arguments']} /ConfigurationFile=#{config_file_path}"
      action :install
    end
  end

service service_name do
  action :nothing
end

# set the static tcp port
registry_key static_tcp_reg_key do
  values [{ :name => 'TcpPort', :type => :string, :data => node['sql_server']['port'].to_s },
    { :name => 'TcpDynamicPorts', :type => :string, :data => '' }]
  notifies :restart, "service[#{service_name}]", :immediately
end

include_recipe 'sql_server::client'

if node['sql_server']['open_firewall']
  windows_batch "MSSQL_Firewall" do
      code <<-EOH
  netsh advfirewall firewall add rule name=\"SQL Server Instance #{node['sql_server']['instance_name']} TCP#{node['sql_server']['port'].to_s}-In\" action=allow protocol=TCP dir=in localport=#{node['sql_server']['port'].to_s}"
      EOH
  end
end
