mongo_directory  = attribute('mongodbPath', default: '/var/lib/mongodb', description: 'Path to the mongodb directory where database file are saved')
mongo_conf_file  = attribute('conf_file', default: '/etc/mongod.conf', description: 'Path to the mongod.conf file')


control "mongod-file-Directories-1" do
    title "Ensure that database file owner and group are set correctly"
    desc "Mongodb Path is a directory where all databases related files are stored in different format.
          The owner and group should be mongod"
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    tag Remedy:"Set ownership of the database file to mongodb user using
                the following commands: sudo chown mongodb:mongodb /var/lib/mongodb"
    ref 'MongodB dbPath', url: 'https://docs.mongodb.com/v3.6/reference/configuration-options/#storage.dbPath'
    describe file(mongo_directory) do
        it { should be_directory }
        its('group') { should eq 'mongodb' }
        its('owner') { should eq 'mongodb' }
      end
    end

control "mongod-file-Directories-2" do
    title "Ensure that database file permission are set correctly"
    desc "Mongodb Path is a directory where all databases related files are stored in different format.
          The mode of this directory should be 770. It should not be readble,executable and writeable by others."
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    tag Remedy:"Remove other permissions using
                the following commands: chmod 770 /var/lib/mongodb"
    ref 'MongodB dbPath', url: 'https://docs.mongodb.com/v3.6/reference/configuration-options/#storage.dbPath'
    describe file(mongo_directory) do
        its('mode') { should cmp '0770' }
        it { should be_readable.by('owner') }
        it { should  be_readable.by('group') }
        it { should_not be_readable.by('other') }
        it { should be_writable.by('owner') }
        it { should_not be_writable.by('other') }
        it { should be_executable.by('owner') }
        it { should be_executable.by('group') }
        it { should_not be_executable.by('other') }
      end
    end

control "mongod-file-Directories-3" do
    title "Ensure that configuration file owner is root and it is not  writable by others"
    desc "mongodB configuration file are very important and if other has permission to write this file then anyone will be 
          able to change the state of mongodB"
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    tag Remedy:"Set ownership of the configuration file to root user and remove other write permissions using
                the following commands: chmod 640 /var/lib/mongodb"
    describe file(mongo_conf_file) do
        its('mode') { should cmp '0644' }
        its('group') { should eq 'root' }
        its('owner') { should eq 'root' }
        it { should_not be_writable.by('other') }
        it { should_not be_writable.by('group') }
      end
    end
