# Copyright © 2026 Björn Victor (bjorn@victor.se)
# This is a library for "persistent worker threads" (based on PythonGuis/Martin Fitzpatrick, see link),
# with an example use class for watching for when user@host on Chaosnet is logged in (and how idle).

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

# The basic classes (WorkerSignals, Worker) by Martin Fitzpatrick are from
# https://www.pythonguis.com/tutorials/multithreading-pyside6-applications-qthreadpool/

debug = False
default_interval = 5

import sys, time, traceback
# pip3 install nocasedict (see https://github.com/pywbem/nocasedict)
from nocasedict import NocaseDict

from PyQt6.QtCore import (
    QObject,
    QRunnable,
    QThread,
    QThreadPool,
    QTimer,
    QMutex, QWaitCondition,
    QCommandLineOption, QCommandLineParser,
    qInfo, qDebug, qWarning, 
    # Signal, # when using PySide6
    # Slot, # when using PySide6
)
# when using PyQt6:
from PyQt6.QtCore import pyqtSignal as Signal, pyqtSlot as Slot

# only for demo use:
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)



class WorkerSignals(QObject):
    """Signals from a running worker thread.

    finished
        int thread_id

    error
        tuple (exctype, value, traceback.format_exc())

    result
        object data returned from processing, anything

    progress
        tuple (thread_id, progress_value)
    """

    finished = Signal(int)  # thread_id
    error = Signal(tuple)
    result = Signal(object)
    progress = Signal(tuple)  # (thread_id, progress_value)

class Worker(QRunnable):
    """Worker thread.

    Inherits from QRunnable to handler worker thread setup, signals and wrap-up.

    :param callback: The function callback to run on this worker thread.
                     Supplied args and
                     kwargs will be passed through to the runner.
    :type callback: function
    :param args: Arguments to pass to the callback function
    :param kwargs: Keywords to pass to the callback function
    """

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        self.thread_id = kwargs.get("thread_id", 0)
        # Add the callback to our kwargs
        self.kwargs["progress_callback"] = self.signals.progress

    @Slot()
    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit(self.thread_id)

class PersistentWorkerSignals(WorkerSignals):
    """Adding some signals for persistent threads."""
    finished = Signal(object)  # make this an object
    new_args = Signal(tuple)
    please_stop = Signal(object)

class PersistentWorker(Worker):
    """Thread that runs a persistent/periodic thread.
    The run function iterates every "interval" seconds, signaling its results,
    and handles a "new_args" signal which can be used to change the arguments of the callback (between runs),
    and a "please_stop" signal for terminating the thread."""

    be_done = False
    interval = 5                # Default interval
    waiting_lock = None
    waiting_condition = None
    debugp = False

    def __init__(self, fn, *args, **kwargs):
        super().__init__(fn, *args, **kwargs)
        self.signals = PersistentWorkerSignals()
        self.interval = kwargs.get("interval", default_interval)
        # Add the callback to our kwargs - using the right self.signals
        self.kwargs["progress_callback"] = self.signals.progress
        # Connect the new signals
        self.signals.please_stop.connect(self.stop_please)
        self.signals.new_args.connect(self.new_args)
        # Set up waiting condition
        self.waiting_lock = QMutex()
        self.waiting_condition = QWaitCondition()

    def set_debug(self, debugp):
        self.debugp = debugp

    def wakeup_call(self):
        # Interrupt the wait between run-function calls
        self.waiting_lock.lock()
        self.waiting_condition.wakeAll()
        self.waiting_lock.unlock()

    def new_args(self, newargs):
        self.args = newargs
        if self.debugp:
            qDebug("new args for worker {!r} are: {!r} {!r}".format(self.args[0] if len(self.args) > 0 else None, self.args, self.kwargs))
        self.wakeup_call()

    def stop_please(self, token=True):
        # Get a token, and pass it back in the finished signal.
        if self.debugp:
            qDebug("worker {!r} asked to stop ({!r})".format(self.args[0] if len(self.args) > 0 else self, token))
        self.be_done = token
        self.wakeup_call()

    def refresh(self):
        self.wakeup_call()

    def set_interval(self, interval):
        if interval >= 0:
            self.interval = interval
            self.wakeup_call()
        else:
            qInfo("Invalid interval, must be positive: {!r}".format(interval))
    def default_interval(self):
        return self.kwargs.get("interval", default_interval)
    def set_default_interval(self):
        self.set_interval(self.default_interval())
    def is_not_paused(self):
        return self.interval < 0x7fffffff # this means paused

    @Slot()
    def run(self):
        # qDebug("run {!r} thread {}".format(self,current_thread()))
        while not self.be_done:
            if self.is_not_paused():
                try:
                    result = self.fn(*self.args, **self.kwargs)
                except Exception as e:
                    if self.debugp:
                        qDebug("Exception {} in {!r}".format(e, self))
                        traceback.print_exc()
                    exctype, value = sys.exc_info()[:2]
                    self.signals.error.emit((exctype, value, traceback.format_exc()))
                else:
                    self.signals.result.emit(result)
            # Use QWaitCondition with timeout for sleeping so e.g. argument updates and interval settings
            # take effect more quickly.
            # Still won't interrupt e.g. a slow connection in the .fn though.
            self.waiting_lock.lock()
            got_wakeup = self.waiting_condition.wait(self.waiting_lock, 
                                                     # seconds if debugging, minutes otherwise
                                                     # @@@@ use a QDeadlineTimer (ms) instead
                                                     round(self.interval*1000 if self.debugp else self.interval*60*1000))
            self.waiting_lock.unlock()
            # Don't really care if it was a timeout or wakeup.
            if self.debugp:
                qDebug("run {!r} {}".format(self.args[0] if len(self.args) > 0 else self, "got wakeup call" if got_wakeup else "got timeout"))
        if self.debugp:
            qDebug("run {!r} finished, be_done {!r}".format(self.args[0] if len(self.args) > 0 else self, self.be_done))
        self.signals.finished.emit(self.be_done)

# Subclass this with your own 'got_result' method.
# It gets a triple: (hostname, host_is_up, [(user,idle_minutes) for user in watched_users])
# and can thus update some status list, keep track of how old statuses are, etc.
class ChaosUserWatcher:
    workers = NocaseDict()          # threads (PersistentWorker) indexed by host
    debugp = False
    # @@@@ init to supply a list of targets - caller can iterate start_watcher
    # @@@@ status meth to get status for a certain target - this goes in the caller (or subclass)

    def __init__(self):
        self.threadpool = QThreadPool()
    def set_debug(self,debugp):
        self.debugp = debugp

    # For each host, run a worker thread that tries:
    # - 1. FINGER (which is fast and gives both host-up and user+idle info)
    # - 2a. if that fails, LOAD (which is fast and tells both host-up and if there is anyone at all)
    # - 2b. if LOAD fails, STATUS (which is fast and tells if host is up)
    # - 3. if LOAD gave any users or STATUS is up, NAME (which is slow and needs parsing, but gives user+idle info)
    def watch_this(self, host, users, progress_callback, interval=None):
        # Runs in Watcher thread, one pass at checking status of users at a host
        from chaosnet import ChaosSocketError, ChaosError, FingerDict, LoadDict, StatusDict, NameDict, parse_idle_time_string
        host_up_this_time = False
        users = list(map(lambda x:x.lower(),users))
        # 1. FINGER. If it responds, it says who is logged in and their idle time.
        progress_callback.emit((host,"FINGER start"))
        try:
            r = FingerDict(host).dict_result()
        except ChaosSocketError as m:
            raise
        except ChaosError as m:
            if self.debugp:
                qDebug("FINGER {}: {}".format(host,m))
            r = None
        if r:
            progress_callback.emit((host,"FINGER: host {} is up user {!r} logged in".format(host, r['uname'])))
            host_up_this_time = True
            if r['uname'].lower() in users:
                progress_callback.emit((host,"FINGER: user {} is logged in, idle {!r}".format(r['uname'],r['idle'])))
                users_logged_in = [(r['uname'],parse_idle_time_string(r['idle']))]
                # done
                return host, host_up_this_time, users_logged_in
        # 2a. LOAD. If it responds and says nobody is logged in, trust it.
        progress_callback.emit((host,"LOAD start"))
        try:
            r = LoadDict(host).dict_result()
        except ChaosSocketError as m:
            raise
        except ChaosError as m:
            if self.debugp:
                qDebug("LOAD {}: {}".format(host,m))
            r = None
        if r:
            progress_callback.emit((host,"LOAD: host {} is up, {} users".format(host, r['users'])))
            host_up_this_time = True
            if r['users'] == 0:
                progress_callback.emit((host,"LOAD: no users".format(r['users'])))
                return host, host_up_this_time, []
        # 2b. STATUS, unless we already know the host is up, to see if it's worth doing NAME
        if not host_up_this_time:
            progress_callback.emit((host,"STATUS start"))
            try:
                r = StatusDict(host).dict_result()
            except ChaosSocketError as m:
                raise
            except ChaosError as m:
                if self.debugp:
                    qDebug("STATUS {}: {}".format(host,m))
                r = None
            if r:
                progress_callback.emit((host,"STATUS: host {} is up".format(host)))
                host_up_this_time = True
        # 3. NAME (this can take time)
        if host_up_this_time:
            start = time.time()
            progress_callback.emit((host,"NAME start"))
            try:
                r = NameDict(host, options=dict(timeout=5)).dict_result()
            except ChaosSocketError as m:
                raise
            except ChaosError as m:
                if self.debugp:
                    qDebug("NAME {}: {}".format(host,m))
                r = None
            if r:
                end = time.time()
                progress_callback.emit((host,"NAME: host {} responded in {:.2f}s, users logged in: {!r}".format(host,
                                                                                                            end-start,
                                                                                                            [d['userid'] for d in r])))
                # return status of the users we're looking for
                return host, host_up_this_time, [(d['userid'],parse_idle_time_string(d['idle']))
                                                 for d in r if d['userid'].lower() in users]
        progress_callback.emit((host,"No methods gave any users, host is {}".format("up" if host_up_this_time else "down")))
        return host, host_up_this_time,[]

    #### Signal handlers

    def got_result(self, result):
        # Handler for result signal.
        # In main thread, get a result: (host, state=up/down, users=[(user,idle)*])
        qInfo("Got a result: {!r}".format(result))
        # (In Converse, update matching conversation tab icons.
        # Keep track of previous status so changes can be reported.)
        pass

    def watcher_finished(self, host):
        # Handler for finished signal.
        if self.debugp:
            qInfo("Watcher finished for {!r}".format(host))
        if host in self.workers:
            w, u = self.workers[host]
            del self.workers[host]
            if self.debugp:
                qDebug("Removed {} from workers, watcher is {!r}".format(host,w))
        else:
            qDebug("Bug: watcher finished for {!r} but that is not a workers key: {!r}".format(
                host, list(self.workers.keys())))

    def watcher_progress(self, data):
        host, info = data
        qInfo("Watcher for {!r} progressed: {!r}".format(host,info))

    def watcher_error(self, data):
        try:
            etype, exc, trace_string = data
        except ValueError:
            pass                # didnt get the triple we're expecting
        else:
            if self.debugp:
                qDebug("Watcher error: {!r} {!r}".format(etype,exc))
            raise etype("Exception in watcher: {!r}".format(exc))

    #### "API" methods

    def set_interval(self, interval):
        if interval > 0:
            for w,_ in self.workers.values():
                w.set_interval(interval)
        else:
            qInfo("Invalid interval {!r} - must be positive".format(interval))

    # Wake up a watcher or all watchers, so they break out of any sleep and check status again.
    def refresh_watcher(self, host):
        if host in self.workers:
            w, _ = self.workers[host]
            w.refresh()
    def refresh_all_watchers(self):
        for w, _ in self.workers.values():
            w.refresh()

    def end_watcher(self, host):
        if host in self.workers:
            watcher, users = self.workers[host]
            if self.debugp:
                qDebug("Telling watcher for {!r} to stop".format(host))
            watcher.signals.please_stop.emit(host)
            # it will be removed from self.workers when it finishes
        else:
            qInfo("No watcher for {!r} found?".format(host))

    def end_all_watchers(self, wait_time=10):
        for host in self.workers:
            self.end_watcher(host)
        # Wait for them to actually end, to avoid RuntimeError in threads
        done = self.threadpool.waitForDone((wait_time)*1000)
        if self.debugp:
            qDebug("Ended all watcher threads: {!r}".format(done))
        
    def pause_watchers(self):
        if self.debugp:
            qInfo("Pausing all watchers")
        self.set_interval(0x7fffffff) # set a high interval
    def unpause_watchers(self):
        if self.debugp:
            qInfo("Unpausing all watchers")
        for w, u in self.workers.values():
            # set default/starting interval
            w.set_default_interval()

    def remove_watcher(self,userathost):
        u,h = userathost.strip().split("@",maxsplit=1)
        u = u.lower()
        # h = h.lower()
        if h in self.workers.keys():
            watcher, users = self.workers[h]
            users.remove(u)
            if self.debugp:
                qDebug("Watcher for {!r} removing {!r} from args: {!r}".format(h,u,users))
            if len(users) == 0:
                if self.debugp:
                    qDebug("No users left to watch, ending watcher for {!r}".format(h))
                self.end_watcher(h)
            else:
                watcher.signals.new_args.emit((h, users))
        else:
            qInfo("Not watching {!r} so can't remove it".format(userathost))

    def start_watcher(self,userathost, interval=None):
        if interval is None:
            interval = default_interval
        u,h = userathost.strip().split("@",maxsplit=1)
        u = u.lower()
        # h = h.lower()
        if h in self.workers.keys():
            watcher, users = self.workers[h]
            if u in users:
                if self.debugp:
                    qInfo("Already watching {!r}, setting interval {}".format(userathost, watcher.default_interval()))
                watcher.set_interval(watcher.default_interval())
            else:
                if self.debugp:
                    qDebug("Watcher for {!r} adding {!r} to args: {!r}".format(h,u,[u]+users))
                self.workers[h] = (watcher,[u]+users)
                watcher.signals.new_args.emit((h,[u]+users))
        else:
            if self.debugp:
                qDebug("Starting watcher for {!r} user {!r}".format(h,u))
            watcher = PersistentWorker(self.watch_this, h, [u], interval=interval)
            watcher.set_debug(self.debugp)
            # watcher.setAutoDelete(False)
            self.workers[h] = (watcher,[u])
            # if self.debugp:
            #     qDebug("Workers {!r}".format(self.workers))
            watcher.signals.result.connect(self.got_result)
            watcher.signals.finished.connect(self.watcher_finished)
            if self.debugp:
                watcher.signals.progress.connect(self.watcher_progress)
            watcher.signals.error.connect(self.watcher_error)
            # Go ahead and watch
            if self.debugp:
                qDebug("Starting {!r}".format(watcher))
            self.threadpool.start(watcher)

class MainWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.counter = 0
        self.thread_id = 0

        layout = QVBoxLayout()

        self.label = QLabel("Starting")
        button = QPushButton("Whatever.")

        layout.addWidget(self.label)
        layout.addWidget(button)

        w = QWidget()
        w.setLayout(layout)
        self.setCentralWidget(w)

        self.show()

        s = ChaosUserWatcher()
        self.s = s
        global debug
        s.set_debug(debug)
        # End all the workers when application quits.
        app.aboutToQuit.connect(s.end_all_watchers)

        s.start_watcher("victor@PUCK")
        s.start_watcher("bv@UP")
        s.start_watcher("bv@cdr")

        # Just keep busy
        self.timer = QTimer()
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.recurring_timer)
        self.timer.start()


    def recurring_timer(self):
        self.counter += 1
        self.label.setText("Counter: {}, threads {}, workers: {}".format(self.counter, 
                                                                          self.s.threadpool.activeThreadCount(),
                                                                          list(self.s.workers.keys())))
        if self.counter == 10:
            self.s.start_watcher("victor@pdpi")
        if self.counter == 15:  # 
            self.s.set_interval(3)
            self.s.start_watcher("victor@UP")
            self.s.start_watcher("bv@bv20")
            self.s.start_watcher("ejs@es")
        if self.counter == 20:
            self.s.remove_watcher("bv@up")
        if self.counter == 25:
            self.s.remove_watcher("victor@puck")
        # if self.counter == 15:
        #     self.s.end_watcher("puck")
        # if self.counter == 25:
        #     self.s.end_watcher("up")

if __name__ == '__main__':
    app = QApplication(sys.argv)

    parser = QCommandLineParser()
    parser.addHelpOption()
    dopt = QCommandLineOption(["d","debug"],"Debug messages")
    iopt = QCommandLineOption(["i","interval"],"Interval","interval")
    parser.addOption(dopt)
    parser.addOption(iopt)
    parser.process(app)
    if parser.isSet(dopt):
        debug = True
    if parser.value(iopt):
        default_interval = int(parser.value(iopt))
    window = MainWindow()
    app.exec()
