# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/csvenrich-ipaddr"

describe LogStash::Filters::CsvenrichIpaddr do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        csvenrich-ipaddr {
          message => "Hello World"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject).to include("message")
      expect(subject.get('message')).to eq('Hello World')
    end
  end
end
