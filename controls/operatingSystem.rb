mongo_conf_file  = attribute('conf_file', default: '/etc/mongod.conf', description: 'Path to the mongod.conf file')
conf_file = yaml(mongo_conf_file)

control 'mongod-Operating-System-Hardening-1' do
    impact 1.0
    title 'mongod should be running and enabled'
    desc 'mongod should be running and enabled. When system restarts apruptly mongod should be started and loaded automatically'
    tag Vulnerability: 'High'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    case os[:name]
    when 'ubuntu'
      case os[:release]
      when '12.04'
        describe command('/etc/init.d/mongod status') do
          its('stdout') { should include 'online' }
        end
      when '14.04'
        describe command('service mongod status') do
          its('stdout') { should include 'online' }
        end
      when '16.04'
        describe systemd_service(postgres.service) do
          it { should be_installed }
          it { should be_running }
          it { should be_enabled }
        end
      # Added for ubuntu 18.04 
      when '18.04'
        describe command('service mongod status') do
          its('stdout') { should include 'active' }
        end
        describe command('systemctl list-unit-files | grep mongod.service') do
          its('stdout') { should include 'enabled' }
        end
      end
    when 'debian'
      case os[:release]
      when /7\./
        describe command('/etc/init.d/mongod status') do
          its('stdout') { should include 'Running' }
        end
      end
    when 'redhat', 'centos', 'oracle', 'fedora'
      case os[:release]
      when /6\./
        describe command('/etc/init.d/mongod-9.4 status') do
          its('stdout') { should include 'running' }
        end
      when /7\./
        describe command('ps aux | awk /\'bin\/postgres\'/ | wc -l') do
          its('stdout') { should include '1' }
        end
      end
    end
  end

control "mongod-Operating-System-Hardening-2" do
    title "Ensure that MongoDB uses a non-default port"
    desc "Changing the default port used by MongoDB makes it harder for attackers to find the
          database and target it."
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    tag Remedy:"Change the port for MongoDB server to a number other than 27017 ."
    ref 'Default mongodb Port', url: 'https://docs.mongodb.com/v3.6/reference/default-mongodb-port/'
    describe conf_file do
    its(["net", "port"]) { should_not eq 27017 }
    end
end


