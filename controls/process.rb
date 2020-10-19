title "Process Security"

control "mongod-process-1" do
  title "Ensure that MongoDB is run using a Least Privileges, dedicated service account i.e mongod"
  desc "The MongoDB process should not run as the root user. We should follow Principle of least priviledge \n
        When a daemon running as root is compromised, the attacker will have root access
        The mitigation is to run the daemon as a non-root user who has the least amount of privilege it needs.
        "
  impact 0.7
  tag Vulnerability: 'Medium'
  tag Remedy:"Create a service file and set user and group to mongodb"
  tag Version: "CIS_MongoDB_3.6_Benchmark_v1.0.0"
  ref 'Why daemon should not run as root', url: 'https://github.com/openbmc/openbmc/issues/3383'
  describe processes("mongod") do
    its("users") { should_not include "root" }
  end
end
