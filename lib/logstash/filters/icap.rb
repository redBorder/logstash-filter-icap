# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require_relative "util/icap_constant"
require_relative "util/aerospike_config"
require_relative "store/aerospike_store"

class LogStash::Filters::Icap < LogStash::Filters::Base
  include IcapConstant
  include Aerospike

  config_name "icap"

  config :aerospike_server,          :validate => :string,  :default => "",                             :required => false
  config :aerospike_namespace,       :validate => :string,  :default => "malware",                      :required => false
  config :counter_store_counter,     :validate => :boolean, :default => false,                          :required => false
  config :flow_counter,              :validate => :boolean, :default => false,                          :required => false
  config :reputation_servers,        :validate => :array,   :default => ["127.0.0.1:7777"],             :require => false

  # DATASOURCE="rb_flow"
  DELAYED_REALTIME_TIME = 15

  public
  def register
    # Add instance variables
    @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
    @aerospike = Client.new(@aerospike_server.first.split(":").first)
    @aerospike_store = AerospikeStore.new(@aerospike, @aerospike_namespace,  @reputation_servers)
  end # def register

  public

  def size_to_range(size)
    range  = nil
    if (size < 1024)
        range =  "<1kB"
    elsif(size >= 1024 && size < (1024*1024))
        range = "1kB-1MB"
    elsif(size >= (1024*1024) && size < (10*1024*1024))
        range = "1MB-10MB"
    elsif(size >= (10*1024*1024) && size < (50*1024*1024))
        range = "10MB-50MB"
    elsif(size >= (50*1024*1024) && size < (100*1024*1024))
        range = "50MB-100MB"
    elsif(size >= (100*1024*1024) && size < (500*1024*1024))
        range = "100MB-500MB"
    elsif(size >= (500*1024*1024) && size < (1024*1024*1024))
        range = "500MB-1GB"
    elsif(size >= (1024*1024*1024))
        range = ">1GB"
    end

    return range
  end

  def filter(event)
    message = {}
    message = event.to_hash

    generated_events = [] 
    enrichment = message["enrichment"]
    file_info = message["file_info"]
    to_druid = {}

    timestamp, hash = nil

    to_druid.merge!enrichment unless enrichment.nil?

    unless file_info.nil?
      to_druid.merge!file_info
      hash = file_info[HASH]
      timestamp = file_info[TIMESTAMP]
    else
      timestamp = Time.now.to_i
      to_druid[TIMESTAMP] = timestamp
    end

    icap_request = message["icap_request_headers"]

    unless icap_request.nil?
      url = icap_request["url_file"]
      dst = icap_request["X-Client-IP"]
      proxy_ip = icap_request["client-ip"]

      to_druid[URL] = url unless url.nil?

      to_druid[DST] = dst unless dst.nil?

      to_druid[PROXY_IP] = proxy_ip unless proxy_ip.nil?
    end

    http_request = message["http_request_headers"]

    unless http_request.nil?
      src = http_request["host"]
      user_agent = http-request["user-agent"]

      to_druid[SRC] = src unless src.nil?

      user_agent[HTTP_USER_AGENT_OS] = user_agent unless user_agent.nil?
    end

    to_druid[TYPE] = "icap"
    to_druid[SENSOR_NAME] = "ICAP"
    to_druid[SENSOR_UUID] = "ICAP"

    @aerospike_store.update_hash_times(timestamp, hash, "hash") unless hash.nil?

    hash_message = @aerospike_store.enrich_hash_scores(to_druid)
    url_message = @aerospike_store.enrich_url_scores(hash_message)
    ip_message = @aerospike_store.enrich_ip_scores(url_message)

    ip_message[APPLICATION_ID_NAME] = "http"
    
    generated_events.push(LogStash::Event.new(ip_message))

    generated_events.each do |e|
      yield e
    end
    event.cancel
  end  # def filter(event)
end # class LogStash::Filters::Icap
