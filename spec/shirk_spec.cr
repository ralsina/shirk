require "./spec_helper"

describe Shirk do
  describe Shirk::Server do
    # TODO: Add server tests
    it "can create a server instance" do
      server = Shirk::Server.new("localhost", 2222, "test_key")
      server.host.should eq("localhost")
      server.port.should eq(2222)
      server.host_key.should eq("test_key")
    end
  end

  describe Shirk::Client do
    it "can create a client instance" do
      client = Shirk::Client.new("localhost", 2222, user: "testuser")
      client.host.should eq("localhost")
      client.port.should eq(2222)
      client.user.should eq("testuser")
    end

    it "has default values" do
      client = Shirk::Client.new("example.com")
      client.host.should eq("example.com")
      client.port.should eq(22)
      client.user.should_not be_empty
      client.timeout.should eq(30)
      client.strict_host_key_checking.should be_false
      client.verbosity.should eq(0)
    end

    it "can configure session options" do
      client = Shirk::Client.new("example.com", 2222, user: "admin", timeout: 60, strict_host_key_checking: true)
      client.host.should eq("example.com")
      client.port.should eq(2222)
      client.user.should eq("admin")
      client.timeout.should eq(60)
      client.strict_host_key_checking.should be_true
    end

    describe Shirk::ExecResult do
      it "creates result correctly" do
        result = Shirk::ExecResult.new("output", "error", 0)
        result.stdout.should eq("output")
        result.stderr.should eq("error")
        result.exit_code.should eq(0)
        result.success?.should be_true
      end

      it "reports failure correctly" do
        result = Shirk::ExecResult.new("output", "error", 1)
        result.success?.should be_false
      end
    end
  end
end
