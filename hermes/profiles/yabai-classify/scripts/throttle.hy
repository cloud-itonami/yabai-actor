#!/usr/bin/env hy
"""Shared cooldown for hourly-scheduled Yabai evidence jobs."""
(import fcntl json os sys time)

(setv STATE-DIR (os.environ.get "HERMES_CRON_THROTTLE_DIR"
                 (os.path.join (os.path.expanduser "~") ".hermes" "cron-throttle")))

(defn state-path [name]
  (setv safe (.join "" (gfor c name :if (or (.isalnum c) (in c "-_.")) c)))
  (os.path.join STATE-DIR (+ safe ".json")))

(defn read-last [name]
  (try
    (with [f (open (state-path name))]
      (float (.get (json.load f) "last-success" 0)))
    (except [OSError ValueError] 0.0)))

(defn gate [name hours]
  "Exit 0 with a THROTTLED banner when the job is not due."
  (setv last (read-last name)
        age-h (if last (/ (- (time.time) last) 3600.0) None))
  (when (and age-h (< age-h hours))
    (print "[SILENT]")
    (print f"THROTTLED\t{name}\tlast success {age-h:.1f}h ago (cooldown {hours}h); nothing to do this tick.")
    (raise (SystemExit 0))))

(defn mark [name]
  "Record a success now; call only after the real work exited successfully."
  (os.makedirs STATE-DIR :exist_ok True)
  (with [f (open (state-path name) "w")]
    (json.dump {"last-success" (time.time) "name" name} f)))

(defclass lock []
  (defn __init__ [self path [name "lock"]]
    (setv self.path path self.name name self.fd None))
  (defn __enter__ [self]
    (os.makedirs (os.path.dirname self.path) :exist_ok True)
    (setv self.fd (os.open self.path (| os.O_CREAT os.O_RDWR) 0o644))
    (try
      (fcntl.flock self.fd (| fcntl.LOCK_EX fcntl.LOCK_NB))
      (except [OSError]
        (print "[SILENT]")
        (print f"THROTTLED\t{self.name}\tanother run holds {self.path}; skipping this tick.")
        (raise (SystemExit 0))))
    self)
  (defn __exit__ [self #* exc]
    (try
      (fcntl.flock self.fd fcntl.LOCK_UN)
      (finally (os.close self.fd)))
    False))
