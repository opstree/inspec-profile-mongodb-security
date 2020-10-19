mongo_conf_file = attribute('conf_file', default: '/etc/mongod.conf', description: 'Path to the mongod.conf file')


title "Network and Communication"

conf_file = yaml(mongo_conf_file)

control "mongod-network-1" do
  title "Ensure Encryption of Data in Transit TLS/SSL"
  desc "Use TLS or SSL to protect all incoming and outgoing connections. This should include using
        TLS or SSL to encrypt communication between the mongod and mongos components of a
        MongoDB client as well as between all applications and MongoDB."
  impact 0.6
  tag Vulnerability: 'Medium'
  tag Remedy: "ssl:
                mode: requireSSL
                PEMKeyFile: /etc/ssl/mongodb.pem"
  ref 'SSL Encryption', url: 'https://docs.mongodb.com/v3.6/core/security-transport-encryption/'

  describe conf_file do
    its(["net", "ssl", "mode"]) { should eq "requireSSL" }
    its(["net", "ssl", "PEMKeyFile"]) { should_not be_nil }
  end
end

# control "mongod-network-2" do
#   title "HTTP-based interfaces are disabled"
#   desc "MongoDB recommends all HTTP-based interfaces are disabled in production to avoid data leakage."
#   tag Vulnerability: 'Low'
#   tag Version: 'Extra Check'
#   ref 'Mongod Realm Service', url: 'https://docs.mongodb.com/realm/services/http/'

#   describe conf_file do
#     its(["net", "http", "enabled"]) { should eq false }
#     its(["net", "http", "JSONPEnabled"]) { should eq false }
#     its(["net", "http", "RESTInterfaceEnabled"]) { should eq false }
#   end
# end

control "mongod-network-3" do
  title "Bind to localhost"
  desc "
    Whenever possible, do not expose MongoDB instances to publicly-accessible interfaces.
    If having MongoDB be accessible to other machines, skip this control.
  "
  tag Vulnerability: 'Medium'
  tag Remedy:"Create a service file and set user and group to mongodb"
  ref 'Why daemon should not run as root', url: 'https://github.com/openbmc/openbmc/issues/3383'
  impact 0.1

  describe conf_file do
    its(["net", "bindIp"]) { should cmp "127.0.0.1" }
  end
end

control "mongod-network-4" do
  title "Wirechecking payload is enabled"
  desc "mongod should validate all requests on receipt to prevent clients inserting malformed data.Setting Wirechecking paylod to true\n
        It validates all requests from clients upon receipt to prevent clients from inserting malformed or invalid BSON into a MongoDB database."
  impact 0.1
  tag Vulnerability: 'Low'
  tag Version: 'Extra checks'
  ref 'See  Wirechecking Section', url: 'https://docs.mongodb.com/manual/reference/configuration-options/#net-options'

  describe conf_file do
    its(["net", "wireObjectCheck"]) { should eq true }
  end
end

control "mongod-network-5" do
  title "Ensure Federal Information Processing Standard"
  desc "The Federal Information Processing Standard (FIPS) is a computer security standard used
        to certify software modules and libraries that encrypt and decrypt data securely. You can
        configure MongoDB to run with a FIPS 140-2 certified library for OpenSSL."
  impact 0.1
  tag Vulnerability: 'Medium'
  tag Remedy:"Add in configuration file
              net:
                ssl:
                FIPSMode: true"
  ref 'MongodB Configure FIPS', url: 'https://docs.mongodb.com/v3.6/tutorial/configure-fips/'

  describe conf_file do
    its(["net", "ssl","FIPSMode"]) { should eq true }
  end
end
