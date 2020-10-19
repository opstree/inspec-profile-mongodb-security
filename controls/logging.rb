mongo_conf_file  = attribute('conf_file', default: '/etc/mongod.conf', description: 'Path to the mongod.conf file')
conf_file = yaml(mongo_conf_file)

control "mongod-logging-1" do
    title "Ensure that system activity is audited"
    desc "MongoDB Enterprise includes a system auditing facility that can record system events (e.g. user operations, \n
          connection events) on a MongoDB instance. These logging enable to track incident happend"
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    tag Remedy:"Set the destinations based on the organization’s requirements.
                mongod --dbpath data/db --auditDestination file --auditFormat JSON --auditPath data/db/auditLog.json
                or you change configuration file and add destination and path of Log"
    ref 'MongodB configure Auditing', url: 'https://docs.mongodb.com/v3.6/tutorial/configure-auditing/'
    describe conf_file do
        its(["systemLog", "destination"]) { should  match(/syslog|file/) }
        its(["systemLog", "destination"]) { should_not  eq "console" }
        end
    end

control "mongod-logging-2" do
    title "Ensure that new entries are appended to the end of the log file"
    desc "By default, new log entries will overwrite old entries after a restart of the mongod or mongos service.\n
         Enabling the systemLog.logAppend setting causes new entries to be appended to the end of the log file rather \n
         than overwriting the existing content of the log when the mongod or mongos instance restarts."
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    tag Remedy:"Set systemLog.logAppend to true in the /etc/mongod.conf file."
    ref 'MongodB configuration Log Append', url: 'https://docs.mongodb.com/v3.6/reference/configuration-options/#systemLog.logAppend'
    describe conf_file do
        its(["systemLog", "logAppend"]) { should  eq true }
        end
    end

control "mongod-logging-3" do
    title "Ensure that logging captures as much information as possible"
    desc "Ensure that logging captures as much information such as connection events, authentication events, replication sync activities
          evidence of some potentially impactful commands being run (eg: drop , dropIndexes , validate )"
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    tag Remedy:"Set SystemLog.quiet to false in the /etc/mongod.conf file to disable it."
    ref 'MongodB configuration systemlog quiet', url: 'https://docs.mongodb.com/v3.6/reference/configuration-options/#systemLog.quiet'
    describe conf_file do
        its(["systemLog", "quiet"]) { should  eq false }
        end
    end

control "mongod-logging-4" do
    title "Ensure that audit filters are configured properly"
    desc "When enabled, the audit facility, by default, records all auditable operations as detailed in Audit Event Actions,
          Details, and Results. To specify which events to record, the audit feature includes the -- auditFilter option"
    impact 1.0
    tag Vulnerability: 'Low'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    tag Remedy:"Set SystemLog.quiet to false in the /etc/mongod.conf file to disable it."
    ref 'MongodB configuration systemlog quiet', url: 'https://docs.mongodb.com/v3.6/reference/configuration-options/#systemLog.quiet'
    describe conf_file do
        its(["auditLog", "destination"]) { should  match(/syslog|file/) }
        its(["auditLog", "filter"]) { should  match(/\*/) }
        
        end
    end

 