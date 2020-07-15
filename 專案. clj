(defproject echelon "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 ;[com.datomic/datomic-free "0.9.5067"]
                 [org.clojure/data.json "0.2.5"]
                 [me.raynes/fs "1.4.4"]
                 [com.rpl/specter "0.0.6"]
                 [instaparse "1.3.2"]
                 [org.clojure/tools.cli "0.3.1"]
                 [org.jordanlewis/data.union-find "0.1.0"]
                 [clj-time "0.7.0"]
                 [environ "0.5.0"]
                 [com.taoensso/timbre "3.2.1"]
                 [incanter "1.5.5"]]
  :plugins [[lein-environ "0.5.0"]]
  :profiles {:dev
             [:user {:jvm-opts ["-Xmx4g" "-Xms1g"]}]
             :prod
             [:user {:jvm-opts ["-Xmx4g" "-Xms1g" "-server"]}]}
  :main echelon.simple)
