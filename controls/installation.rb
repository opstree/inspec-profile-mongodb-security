control "mongod-installation-1" do
    title "Latest version of mongodB is installed or not"
    desc "Using the most recent MongoDB software version along with all applicable patches, helps \n
          limit the possibilities for vulnerabilities in the software. The installation version \n
          patches applied should be selected according to the needs of the organization."
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    tag Remedy:"1. Backup the data set.\n
                2. Download the binaries for the latest MongoDB revision from the MongoDB Download Page and store \n
                   the binaries in a temporary location. The binaries download as compressed files that extract to the directory structure used by the
                   MongoDB installation.
                3. Shutdown the MongoDB instance.
                4. Replace the existing MongoDB binaries with the downloaded binaries.
                5. Restart the MongoDB instance"
    ref 'MongodB upgrade to Newer Version', url: 'https://docs.mongodb.com/manual/tutorial/upgrade-revision/'
    describe command('mongod --version') do
        its('stdout') { should match(/db version v4.4.?/)  }
        
      end
    end

