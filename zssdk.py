import re
import urllib3
import string
import json
from uuid import uuid4
import time
import threading
import functools
import traceback

CONFIG_HOSTNAME = 'hostname'
CONFIG_PORT = 'port'
CONFIG_POLLING_TIMEOUT = 'default_polling_timeout'
CONFIG_POLLING_INTERVAL = 'default_polling_interval'
CONFIG_WEBHOOK = 'webhook'
CONFIG_READ_TIMEOUT = 'read_timeout'
CONFIG_WRITE_TIMEOUT = 'write_timeout'

HEADER_JOB_UUID = "X-Job-UUID"
HEADER_WEBHOOK = "X-Web-Hook"
HEADER_JOB_SUCCESS = "X-Job-Success"
HEADER_AUTHORIZATION = "Authorization"
OAUTH = "OAuth"
LOCATION = "location"

HTTP_ERROR = "sdk.1000"
POLLING_TIMEOUT_ERROR = "sdk.1001"
INTERNAL_ERROR = "sdk.1002"

__config__ = {}


class SdkError(Exception):
    pass


def _exception_safe(func):
    @functools.wraps(func)
    def wrap(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception:
            print traceback.format_exc()

    return wrap


def _error_if_not_configured():
    if not __config__:
        raise SdkError('call configure() before using any APIs')


def _http_error(status, body=None):
    err = ErrorCode()
    err.code = HTTP_ERROR
    err.description = 'the http status code[%s] indicates a failure happened' % status
    err.details = body
    return {'error': err}


def _error(code, desc, details):
    err = ErrorCode()
    err.code = code
    err.desc = desc
    err.details = details
    return {'error': err}


def configure(
        hostname='127.0.0.1',
        port=8080,
        polling_timeout=3600*3,
        polling_interval=1,
        read_timeout=None,
        write_timeout=None,
        web_hook=None
):
    __config__[CONFIG_HOSTNAME] = hostname
    __config__[CONFIG_PORT] = port
    __config__[CONFIG_POLLING_TIMEOUT] = polling_timeout
    __config__[CONFIG_POLLING_INTERVAL] = polling_interval
    __config__[CONFIG_WEBHOOK] = web_hook
    __config__[CONFIG_READ_TIMEOUT] = read_timeout
    __config__[CONFIG_WRITE_TIMEOUT] = write_timeout


class ParamAnnotation(object):
    def __init__(
            self,
            required=False,
            valid_values=None,
            valid_regex_values=None,
            max_length=None,
            min_length=None,
            non_empty=None,
            null_elements=None,
            empty_string=None,
            number_range=None,
            no_trim=False
    ):
        self.required = required
        self.valid_values = valid_values
        self.valid_regex_values = valid_regex_values
        self.max_length = max_length
        self.min_length = min_length
        self.non_empty = non_empty
        self.null_elements = null_elements
        self.empty_string = empty_string
        self.number_range = number_range
        self.no_trim = no_trim


class ErrorCode(object):
    def __init__(self):
        self.code = None
        self.description = None
        self.details = None
        self.cause = None


class Obj(object):
    def __init__(self, d):
        for a, b in d.items():
            if isinstance(b, (list, tuple)):
                setattr(self, a, [Obj(x) if isinstance(x, dict) else x for x in b])
            else:
                setattr(self, a, Obj(b) if isinstance(b, dict) else b)


class AbstractAction(object):
    def __init__(self):
        self.apiId = None
        self.sessionId = None
        self.systemTags = None
        self.userTags = None
        self.resourceUuid = None
        self.timeout = None
        self.pollingInterval = None

        self._param_descriptors = {
            'sessionId': ParamAnnotation(required=self.NEED_SESSION),
            'systemTags': ParamAnnotation(),
            'userTags': ParamAnnotation(),
            'resourceUuid': ParamAnnotation()
        }.update(self.PARAMS)

    def _check_params(self):
        for param_name, annotation in self._param_descriptors:
            value = getattr(self, param_name, None)

            if value is None and annotation.required:
                raise SdkError('missing a mandatory parameter[%s]' % param_name)

            if value is not None and annotation.valid_values and value not in annotation.valid_values:
                raise SdkError('invalid parameter[%s], the value[%s] is not in the valid options%s' % (param_name, value, annotation.valid_values))

            if value is not None and isinstance(value, str) and annotation.max_length and len(value) > annotation.max_length:
                raise SdkError('invalid length[%s] of the parameter[%s], the max allowed length is %s' % (len(value), param_name, annotation.max_length))

            if value is not None and isinstance(value, str) and annotation.max_length and len(value) > annotation.min_length:
                raise SdkError('invalid length[%s] of the parameter[%s], the minimal allowed length is %s' % (len(value), param_name, annotation.min_length))

            if value is not None and isinstance(value, list) and annotation.non_empty is True and len(value) == 0:
                raise SdkError('invalid parameter[%s], it cannot be an empty list' % param_name)

            if value is not None and isinstance(value, list) and annotation.null_elements is True and None in value:
                raise SdkError('invalid parameter[%s], the list cannot contain a null element' % param_name)

            if value is not None and isinstance(value, str) and annotation.empty_string is False and len(value) == 0:
                raise SdkError('invalid parameter[%s], it cannot be an empty string' % param_name)

            if value is not None and isinstance(value, int) or isinstance(value, long) and len(annotation.number_range) == 2:
                low = annotation.number_range[0]
                high = annotation.number_range[1]
                if value < low or value > high:
                    raise SdkError('invalid parameter[%s], its value is not in the valid range' % annotation.number_range)

            if value is not None and isinstance(value, str) and annotation.no_trim is False:
                value = str(value).strip()
                setattr(self, param_name, value)

    def _params(self):
        ret = {}
        for k, _ in self._param_descriptors:
            val = getattr(self, k, None)
            if val is not None:
                ret[k] = val

        return ret

    def _url(self):
        elements = ['http://', __config__[CONFIG_HOSTNAME], __config__[CONFIG_PORT]]

        path = self.PATH.replace('{', '${')
        unresolved = re.findall('${(.+?)}', path)
        params = self._params()
        if unresolved:
            for u in unresolved:
                if u in params:
                    raise SdkError('missing a mandatory parameter[%s]' % u)

        path = string.Template(path).substitute(params)
        elements.append(path)

        if self.HTTP_METHOD == 'GET' or self.HTTP_METHOD == 'DELETE':
            elements.append('?')
            elements.append('&'.join(['%s=%s' % (k, v) for k, v in params]))

        return ''.join(elements), unresolved

    def call(self, cb=None):

        def _return(result):
            if cb:
                cb(result)
            else:
                return result

        _error_if_not_configured()

        self._check_params()
        url, params_in_url = self._url()

        headers = {}
        if self.apiId is not None:
            headers[HEADER_JOB_UUID] = self.apiId
        else:
            headers[HEADER_JOB_UUID] = _uuid()

        web_hook = __config__.get(CONFIG_WEBHOOK, None)
        if web_hook is not None:
            headers[CONFIG_WEBHOOK] = web_hook

        params = self._params()
        body = None
        if self.HTTP_METHOD == 'POST' or self.HTTP_METHOD == 'PUT':
            m = {}
            for k, v in params:
                if v is None:
                    continue

                if k in params_in_url:
                    continue

                m[k] = v

            body = {self.PARAM_NAME: m}

        if not self.timeout:
            self.timeout = __config__[CONFIG_READ_TIMEOUT]

        rsp = _json_http(uri=url, body=body, headers=headers, method=self.HTTP_METHOD, timeout=self.timeout)

        if rsp.status < 200 or rsp.status >= 300:
            return _return(Obj(_http_error(rsp.status, rsp.body)))
        elif rsp.status == 200 or rsp.status == 204:
            # the API completes
            return _return(Obj(self._write_result(rsp)))
        elif rsp.status == 202:
            # the API needs polling
            return self._poll_result(rsp, cb)
        else:
            raise SdkError('[Internal Error] the server returns an unknown status code[%s], body[%s]' % (rsp.status, rsp.body))

    def _write_result(self, rsp):
        if rsp.status == 200:
            return {"value": json.loads(rsp.body)}
        elif rsp.status == 503:
            return json.loads(rsp.body)
        else:
            raise SdkError('unknown status code[%s]' % rsp.status)

    def _poll_result(self, rsp, cb):
        if not self.NEED_POLL:
            raise SdkError('[Internal Error] the api is not an async API but the server returns 202 status code')

        m = json.loads(rsp.body)
        location = m[LOCATION]
        if not location:
            raise SdkError("Internal Error] the api[%s] is an async API but the server doesn't return the polling location url")

        if cb:
            # async polling
            self._async_poll(location, cb)
        else:
            # sync polling
            return self._sync_polling(location)

    def _fill_timeout_parameters(self):
        if self.timeout is None:
            self.timeout = __config__.get(CONFIG_POLLING_TIMEOUT)

        if self.pollingInterval is None:
            self.pollingInterval = __config__.get(CONFIG_POLLING_INTERVAL)

    def _async_poll(self, location, cb):
        self._fill_timeout_parameters()

        timer = None
        count = [0]

        def _cancel():
            timer.cancel()

        @_exception_safe
        def _polling():
            rsp = _json_http(
                uri=location,
                headers={HEADER_AUTHORIZATION: "%s %s" % (OAUTH, self.sessionId)}
            )

            if rsp.status not in [200, 503, 202]:
                cb(Obj(_http_error(rsp.status, rsp.body)))
                _cancel()
            elif rsp.status in [200, 503]:
                cb(Obj(self._write_result(rsp)))
                _cancel()
            else:
                count[0] += self.pollingInterval
                if count[0] >= self.timeout:
                    cb(Obj(_error(POLLING_TIMEOUT_ERROR, 'polling an API result time out',
                                  'failed to poll the result after %s seconds' % self.timeout)))
                    _cancel()

        timer = threading.Timer(_polling, self.pollingInterval)
        timer.start()

    def _sync_polling(self, location):
        count = 0
        self._fill_timeout_parameters()

        while count < self.timeout:
            rsp = _json_http(
                uri=location,
                headers={HEADER_AUTHORIZATION: "%s %s" % (OAUTH, self.sessionId)}
            )

            if rsp.status not in [200, 503, 202]:
                return Obj(_http_error(rsp.status, rsp.body))

            time.sleep(self.pollingInterval)
            count += self.pollingInterval

        return Obj(_error(POLLING_TIMEOUT_ERROR, 'polling an API result time out',
                          'failed to poll the result after %s seconds' % self.timeout))


class QueryAction(AbstractAction):
    def __init__(self):
        super(QueryAction, self).__init__()


def _uuid():
    return str(uuid4()).replace('-', '')


def _json_http(
        uri,
        body=None,
        headers={},
        method='POST',
        timeout=120.0
):
    pool = urllib3.PoolManager(timeout=timeout, retries=urllib3.util.retry.Retry(15))
    headers.update({'Content-Type': 'application/json', 'Connection': 'close'})

    if body is not None and not isinstance(body, str):
        body = json.dumps(body).encode('utf-8')

    if body:
        headers['Content-Length'] = len(body)
        return pool.request(method, uri, body=body, headers=headers)
    else:
        return pool.request(method, uri, headers=headers)


class CreateZoneAction(AbstractAction):

    HTTP_METHOD = 'POST'
    PATH = '/zones'
    NEED_SESSION = True,
    NEED_POLL = True,
    PARAM_NAME = 'params'

    PARAMS = {
        'name': ParamAnnotation(required=True, max_length=255),
        'description': ParamAnnotation(max_length=2048)
    }

    def __init__(self):
        super(CreateZoneAction, self).__init__()
        self.name = None
        self.description = None


