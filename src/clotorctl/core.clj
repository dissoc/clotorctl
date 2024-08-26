(ns clotorctl.core
  (:require
   [buddy.core.codecs :as codecs])
  (:import
   (java.net StandardProtocolFamily UnixDomainSocketAddress)
   (java.nio ByteBuffer)
   (java.nio.channels SocketChannel)))

(defn connect []
  (let [socket-address (UnixDomainSocketAddress/of "/var/run/tor/control-sock")
        channel        (SocketChannel/open StandardProtocolFamily/UNIX)]
    (def socket-channel channel)
    (.connect channel socket-address)
    channel))

(def command "PROTOCOLINFO\r\n")

(defn send-message [^SocketChannel channel message]
  (let [buf (ByteBuffer/allocate 4024)]
    (.clear buf)
    (.put buf (.getBytes (str message "\r\n")))
    (.flip buf)
    (while (.hasRemaining buf)
      (.write channel buf))))

(defn read-message [^SocketChannel channel]
  (let [buf (ByteBuffer/allocate 4024)]
    (.clear buf)
    (let [bytes-read (.read channel buf)]
      (when (> bytes-read 0)
        (let [b-array (byte-array bytes-read)]
          (.flip buf)
          (.get buf b-array)
          (new String b-array))))))

(defn cookie-path->hex [path]
  (with-open [in (clojure.java.io/input-stream (clojure.java.io/file path))]
    (let [buf (byte-array 32)
          n (.read in buf)]
      (codecs/bytes->hex buf))))

(defn authenticate-cookie-file [client cookie-hex]
  (let [message (str "AUTHENTICATE " cookie-hex )]
    (send-message client message )
    (= "250 OK\r\n" (read-message client))))

(defn get-info [client keywords]
  (let [msg (str "GETINFO " (clojure.string/join " " keywords) "\r\n")]
    (send-message client msg)))

(defn start []
  (let [client (connect)
        cookie-hex (cookie-path->hex "/var/lib/tor/control_auth_cookie")]
    (authenticate-cookie-file client cookie-hex)))

(defn add-onion
  [port-in port-dest
   & {:keys [host-dest priv-key key-type v3-auth flags client-auths-v3 debug?]
      :or   {host-dest "127.0.0.1"
             v3-auth   true
             key-type  "NEW"
             debug? false}}]
  (let [conn       (connect)
        cookie-hex (cookie-path->hex "/var/lib/tor/control_auth_cookie")
        authed?    (authenticate-cookie-file conn cookie-hex)]
    (when authed?
      (let [message (clojure.string/join " "
                                         (remove nil?
                                                 (concat
                                                  (list "ADD_ONION"
                                                        (str key-type
                                                             ":"
                                                             (if (= "NEW" key-type)
                                                               "BEST"
                                                               priv-key))

                                                        (when (not-empty flags)
                                                          (str "Flags="
                                                               (clojure.string/join ","
                                                                                    flags)))
                                                        (str "Port=" port-in "," host-dest ":" port-dest))
                                                  (when client-auths-v3
                                                    (map (fn [k]
                                                           (str "ClientAuthV3=" k))
                                                         client-auths-v3)))))]
        (when debug? (println "Sending message to to: " message))
        (send-message conn message))
      ;; parse the result
      (try (let [result (-> (read-message conn)
                            clojure.string/split-lines)]
             (if (not (every?  #(clojure.string/starts-with? % "250") result))
               (throw (Exception. (str "Bad response:" result)))
               (let [onion (reduce
                            (fn [m v]
                              (cond
                                (clojure.string/starts-with? v "250-ServiceID")
                                (assoc m :onion-address (-> v
                                                            (clojure.string/split #"=" 2)
                                                            second))
                                (clojure.string/starts-with? v "250-PrivateKey")
                                (let [private-key (-> v
                                                      (clojure.string/split #"=" 2)
                                                      second
                                                      (clojure.string/split #":" 2))]

                                  (assoc m :private-key {:type (first private-key)
                                                         :key  (second private-key)}))
                                :else m))
                            {}
                            result)]
                 (.close conn)
                 onion)))))))

(defn delete-onion
  [service-id]
  (let [conn       (connect)
        cookie-hex (cookie-path->hex "/var/lib/tor/control_auth_cookie")
        authed?    (authenticate-cookie-file conn cookie-hex)]
    (when authed?
      (let [message (str "DEL_ONION " service-id)]
        (send-message conn message))
      ;; parse the result
      (try (let [message (-> (read-message conn)
                             clojure.string/trim-newline
                             (clojure.string/split #" "))]
             (.close conn)
             {:status  (-> message
                           first)
              :message (->> message
                            rest
                            (clojure.string/join " "))})))))

(defn client-auth-add
  [{:keys [hs-address key-type private-key-blob flags nickname]
    :or   {key-type "x25519"}}]
  (let [conn       (connect)
        cookie-hex (cookie-path->hex "/var/lib/tor/control_auth_cookie")
        authed?    (authenticate-cookie-file conn cookie-hex)]
    (when authed?
      (let [message (clojure.string/join " " (remove nil? (list "ONION_CLIENT_AUTH_ADD"
                                                                hs-address
                                                                (str key-type ":" private-key-blob)
                                                                (when nickname
                                                                  (str "ClientName=" nickname))
                                                                (when flags
                                                                  (str "Flags=" flags)))))]
        (send-message conn message))
      ;; parse the result
      (try (let [result (-> (read-message conn)
                            clojure.string/split-lines)]
             (println result)
             (if (not (every?  #(clojure.string/starts-with? % "250") result))
               (throw (Exception. "Bad response"))
               (let [onion (reduce
                            (fn [m v]
                              (cond
                                (clojure.string/starts-with? v "250-ServiceID")
                                (assoc m :onion-address (-> v
                                                            (clojure.string/split #"=" 2)
                                                            second))
                                (clojure.string/starts-with? v "250-PrivateKey")
                                (let [private-key (-> v
                                                      (clojure.string/split #"=" 2)
                                                      second
                                                      (clojure.string/split #":" 2))]
                                  (assoc m :private-key {:type (first private-key)
                                                         :key  (second private-key)}))
                                :else m))
                            {}
                            result)]
                 (.close conn)
                 onion)))))))
