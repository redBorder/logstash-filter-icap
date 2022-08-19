# encoding: utf-8
require "aerospike"
require "manticore"
require "json"
require_relative "../util/malware_constant"

class AerospikeStore
  include MalwareConstant
  include Aerospike

  attr_accessor :aerospike

  def initialize(aerospike, namespace = "malware", reputation_servers)
    @aerospike = aerospike
    @namespace = namespace 
    @reputation_servers = reputation_servers

    # Create index
    @aerospike.create_index(@namespace, "hashScores", "index_hash_score", "score", :numeric)
    @aerospike.create_index(@namespace, "hashScores", "index_hash_list", "list_type", :string)
    @aerospike.create_index(@namespace, "urlScores", "index_url_score", "score", :numeric)
    @aerospike.create_index(@namespace, "urlScores", "index_url_list", "list_type", :string)
    @aerospike.create_index(@namespace, "ipScores", "index_ip_score", "score", :numeric)
    @aerospike.create_index(@namespace, "ipScores", "index_ip_list", "list_type", :string)
    @aerospike.create_index(@namespace, "controlFiles", "index_hash_controlFiles", "hash", :string)

    @aerospike.create_index(@namespace, "mailQuarantine", "index_mail_quarantine", "sensor_uuid", :string)
  end

  def update_hash_times(timestamp, data, type)
    unless data.nil?
      hash_times_key = Key.new(@namespace, type + "Times" , data) rescue nil
      data_times = {}
      data_times[type] = data

      if hash_times_key
        data_times["time_end"] = timestamp
      else
        data_times["time_start"] = timestamp
        data_times["time_end"] = timestamp
      end

      @aerospike.put(hash_times_key, data_times)
    end
  end

  def enrich_ip_scores(message) 
    data = {}
    data.merge!message

    src = message["src"]
    dst = message["dst"]

    src_key = Key.new(@namespace, "ipScores", src) rescue nil
    dst_key = Key.new(@namespace, "ipScores", dst) rescue nil

    if (!src.nil? and !dst.nil?)
      
      data_src = @aerospike.get(src_key).bins rescue {}
      data_dst = @aerospike.get(dst_key).bins rescue {}

      score_src, score_dst = -1

      if !data_src.empty?
        score_src = data_src[SCORE]
        data_src.delete(SCORE)
        list_type_src = data_src[LIST_TYPE]
        data_src.delete(LIST_TYPE)

        unless list_type_src.nil?
          if list_type_src == "black"
            score_src = 100
          elsif list_type_src == "white"
            score_src = 0
          end
          data["ip_"+LIST_TYPE] = list_type_src
        else
          data["ip_"+LIST_TYPE] = "none"
        end
      else
        score_src = -1
        params = {}
        params["http"] = "asynchronous"
        params["process"] = "complete"
        params["ip"] = src

        Manticore.post(make_random_reputation_url, body: params.to_json.to_s).body
      end

      if !data_dst.nil?
        score_dst = data_dst[SCORE]
        data_dst.delete(SCORE)
        list_type_dst = data_dst[LIST_TYPE]
        data_dst.delete(LIST_TYPE)

        unless list_type_dst.nil?
          if list_type_dst == "black"
            score_dst = 100
          elsif list_type_dst == "white"
            score_dst = 0
          end
          data["ip_"+LIST_TYPE] = list_Type_dst
        else
          data["ip_"+LIST_TYPE] = "none"
        end
      else
        score_dst = -1
        params = {}
        params["http"] = "asynchronous"
        params["process"] =  "complete"
        params["ip"] = dst

        Manticore.post(make_random_reputation_url, body: params.to_json.to_s).body
      end
      
      score_src = -1 unless score_src
      score_dst = -1 unless score_dst

      if (score_src > 0 and score_dst > 0)
        data[IP_DIRECTION] = "both"
        if score_src > score_dst
          data["ip_"+SCORE]  = score_src
        else
          data["ip_"+SCORE] = score_dst
        end
      elsif score_src > 0
        data[IP_DIRECTION] = "source"
        data["ip_"+SCORE] = score_src
      elsif score_dst > 0
        data[IP_DIRECTION] = "destination"
        data["ip_"+SCORE] = score_dst
      else
        data[IP_DIRECTION] = "none"
        data["ip_"+SCORE] = -1
      end

    elsif !src.nil?
      data_src = @aerospike.get(src_key).bins rescue {}

      unless data_src.empty?
        score_src = data_src[SCORE]
        data_src.delete(SCORE)
        list_type_src = data_src[LIST_TYPE]
        #TODO: we dont need to delete list_type_src??
        
        unless list_type_src.nil?
          if list_type_src == "black" 
            score_src = 100
          elsif list_type_src == "white"
            score_src = 0
          end
          data["ip_"+LIST_TYPE] =  list_type_src
        else
          data["ip_"+LIST_TYPE] = "none"
        end

        score_src = -1 unless score_src

        if (score_src > 0)
          data[IP_DIRECTION] = "source"
          data["ip_"+SCORE] = score_src
        else
          data[IP_DIRECTION] = "none"
          data["ip_"+SCORE] = -1
        end
      else
        data[IP_DIRECTION] = "none"
        data["ip_"+SCORE] = -1

        params = {}
        params["http"] = "asynchronous"
        params["process"] = "complete"
        params["ip"] = src

        Manticore.post(make_random_reputation_url, body: params.to_json.to_s).body
      end

      params = {}
      params["http"] = "asynchronous"
      params["process"] = "complete"
      params["ip"] = dst

      Manticore.post(make_random_reputation_url, body: params.to_json.to_s).body

    elsif !dst.nil?
      data_dst = @aerospike.get(dst_key).bins rescue {}
      score_dst = data_dst[SCORE] rescue nil
      data_dst.delete(SCORE)
      list_type_src = data_dst[LIST_TYPE]
      data_dst.delete(LIST_TYPE)

      unless data_dst.empty?
        unless list_type_src.nil?
          if list_type_src == "black"
            score_dst = 100
          elsif list_type_src == "white"
            score_dst = 0
          end
          data["ip_"+LIST_TYPE] = list_type_src
        else
          data["ip_"+LIST_TYPE] = "none"
        end

        score_dst = -1 unless score_dst

        if score_dst > 0
          data[IP_DIRECTION] = "destionation"
          data["ip_"+SCORE] = score_dst
        else
          data[IP_DIRECTION] = "none"
          data["ip_"+SCORE] = -1
        end

      else
        data[IP_DIRECTION] = "none"
        data["ip_"+SCORE] = -1

        params = {}
        params["http"] = "asynchronous"
        params["process"] = "complete"
        params["ip"] = dst

        Manticore.post(make_random_reputation_url, body: params.to_json.to_s).body
      end
    end
    
    return data
  end


  def enrich_hash_scores(message)
    data = {}
    data.merge!(message)

    hash = message["hash"]

    unless hash.nil?
      hash_key = Key.new(@namespace,"hashScores", hash) rescue nil

      data_hash = @aerospike.get(hash_key).bins rescue {}

      unless data_hash.empty?
        list_type = data_hash[LIST_TYPE]
        data_hash.delete(LIST_TYPE)
        score = data_hash[SCORE]
        data_hash.delete(SCORE)

        unless list_type.nil?
          if list_type == "black"
            score = 100
          elsif list_type == "white"
            score = 0
          end
          data["hash_"+LIST_TYPE] = list_type
        else
          data["hash_"+LIST_TYPE] = "none"
        end
        
        score = -1 unless score

        data["hash_"+SCORE] = score

      else
        data["hash_"+SCORE] = -1
        data[LIST_TYPE] = "none"

        params = {}
        params["http"] = "asynchronous"
        params["process"] = "complete"
        params["hash"] = hash

        Manticore.post(make_random_reputation_url, body: params.to_json.to_s).body
      end
    end

    return data
  end

  def enrich_url_scores(message)
    data = {}
    data.merge!message
    url = message["url"]

    unless url.nil?
      url_key = Key.new(@namespace, "urlScores", url) rescue nil

      url_hash = @aerospike.get(url_key).bins rescue {}

      unless url_hash.empty?
        list_type = url_hash[LIST_TYPE]
        url_hash.delete(LIST_TYPE)
        score = url_hash[SCORE]

        unless list_type.nil?
          if list_type == "black"
            score = 100
          elsif list_type == "white"
            score = 0
          end
          data["url_"+LIST_TYPE] = list_type
        else
          data["url_"+LIST_TYPE] = "none"
        end

        score = -1 unless score
        data["url_"+SCORE] = score
      else
        data ["url_"+SCORE] = -1
        data[LIST_TYPE] = "none"

        params = {}
        params["http"] = "asynchronous"
        params["process"] = "complete"
        params["url"] = url

        Manticore.post(make_random_reputation_url, body: params.to_json.to_s).body
      end
    end


    return data
  end

  def make_random_reputation_url
    random_reputation_server = @reputation_servers.sample
    return "http://#{random_reputation_server}/reputation/v1/malware/query";
  end
end
