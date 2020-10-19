mongo_username = attribute('username', default: nil, description: 'User with which to log in to MongoDB')
mongo_password = attribute('password', default: nil, description: 'Password with which to log in to MongoDB')
mongo_verify_ssl = attribute('verify_ssl', default: true, description: 'If true, SSL certificates will be validated')
mongo_conf_file  = attribute('conf_file', default: '/etc/mongod.conf', description: 'Path to the mongod.conf file')

title "Access Control and Authentication"

control "mongod-auth-1" do
  title "Authentication is enabled"
  desc "Authentication should be enabled and required for any interaction with mongod.
        It ensures that all clients, users, servers are required to authenticate before being
        granted access to the MongoDB database."
  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
  tag Remedy:"Open mongod.conf and change for authorization value to enabled"
  ref 'Mongodb Authentication', url: 'https://docs.mongodb.com/v3.6/core/authentication/'

  describe yaml(mongo_conf_file) do
    its(["security", "authorization"]) { should cmp "enabled" }
  end
end

control "mongod-auth-2" do
  title "Unauthenticated connections are denied"
  desc "Connections that do not contain a valid username and password should be rejected."
  impact 1.0

  describe mongo_command("db.getUser('#{mongo_username}')", allow_auth_errors: true, verify_ssl: mongo_verify_ssl) do
    its("stdout") { should include "Error: not authorized"}
  end

  # only_if do
  #   !mongo_username.nil?
  # end
end

# These checks are not accurate and also they are being executed on 127.0.0.1 bind address,
# Host part is required to add 

# control "mongod-auth-3" do
#   title "Multiple user accounts exist"
#   desc "A single administrator user should be created, and then
#     individual accounts should be created for each specific use
#     of MongoDB. Therefore, there should be at least two users
#     created."
#   impact 0.7

#   describe mongo_command("db.getUsers()", username: mongo_username, password: mongo_password, host: "18.222.239.69" ,verify_ssl: mongo_verify_ssl) do
#     its("params.length") { should be >= 2 }
#   end
# end

# control "mongod-auth-4" do
#   title "Roles are used"
#   desc "Role-based access control should be used. Therefore, at
#     least 1 role should be created."
#   impact 0.7

#   describe mongo_command("db.getRoles()", username: mongo_username, password: mongo_password, verify_ssl: mongo_verify_ssl) do
#     its("params.length") { should be >= 1 }
#   end
# end

