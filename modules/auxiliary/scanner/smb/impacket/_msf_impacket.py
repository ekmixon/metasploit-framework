import logging
import ntpath
import time

import metasploit.module as module

OUTPUT_FILENAME = f'__{str(time.time())}'


def pre_run_hook(args):
    if 'rhost' in args:
        module.LogHandler.setup(msg_prefix="{0} - ".format(args['rhost']))
    else:
        module.LogHandler.setup()

class RemoteShell(object):
    def __init__(self, share, transferClient):
        self._share = share
        self._output = '\\' + OUTPUT_FILENAME
        self._outputBuffer = ''

        self.__transferClient = transferClient
        self._noOutput = False

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(100000)
            self.do_cd('\\')
        else:
            self._noOutput = True

    def do_cd(self, s):
        self.execute_remote(f'cd {s}')
        if len(self._outputBuffer.strip('\r\n')) <= 0:
            self._pwd = ntpath.normpath(ntpath.join(self._pwd, s))
            self.execute_remote('cd ')
            self._pwd = self._outputBuffer.strip('\r\n')
        self._outputBuffer = ''

    def do_get(self, src_path):
        try:
            newPath = ntpath.normpath(ntpath.join(self._pwd, src_path))
            drive, tail = ntpath.splitdrive(newPath)
            filename = ntpath.basename(tail)
            with open(filename, 'wb') as fh:
                logging.info("Downloading %s\\%s" % (drive, tail))
                self.__transferClient.getFile(f'{drive[:-1]}$', tail, fh.write)
        except Exception as e:
            logging.error(str(e))
            if os.path.exists(filename):
                os.remove(filename)

    def do_put(self, s):
        try:
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = ''

            src_file = os.path.basename(src_path)
            with open(src_path, 'rb') as fh:
                dst_path = string.replace(dst_path, '/', '\\')

                pathname = ntpath.join(ntpath.join(self._pwd, dst_path), src_file)
                drive, tail = ntpath.splitdrive(pathname)
                logging.info(f"Uploading {src_file} to {pathname}")
                self.__transferClient.putFile(f'{drive[:-1]}$', tail, fh.read)
        except Exception as e:
            logging.critical(str(e))

    def do_exit(self, _):
        return True

    def onecmd(self, line):
        self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self._outputBuffer += data.decode("utf-8")

        if self._noOutput is True:
            self._outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self._share, self._output, output_callback)
                break
            except Exception as e:
                if 'STATUS_SHARING_VIOLATION' in str(e):
                    # Output not finished, let's wait
                    time.sleep(1)
                elif 'Broken' in str(e):
                    # The SMB Connection might have timed out, let's try reconnecting
                    logging.debug('Connection broken, trying to recreate it')
                    self.__transferClient.reconnect()
                    return self.get_output()
        self.__transferClient.deleteFile(self._share, self._output)

    def send_data(self, data):
        self.execute_remote(data)
        if self._noOutput is False:
            module.log(self._outputBuffer)
        self._outputBuffer = ''
