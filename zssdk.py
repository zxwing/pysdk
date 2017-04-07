

CONFIG_HOSTNAME = 'hostname'
CONFIG_PORT = 'port'
CONFIG_POLLING_TIMEOUT = 'default_polling_timeout'
CONFIG_POLLING_INTERVAL = 'default_polling_interval'
CONFIG_WEBHOOK = 'webhook'
CONFIG_READ_TIMEOUT = 'read_timeout'
CONFIG_WRITE_TIMEOUT = 'write_timeout'

__config__ = {}


class SdkError(Exception):
    pass


class HttpError(Exception):
    def __init__(self, status, body=None):
        self.status = status
        self.body = body


def _error_if_not_configured():
    if not __config__:
        raise SdkError('call configure() before using any APIs')


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




class QueryAction(AbstractAction):
    def __init__(self):
        super(QueryAction, self).__init__()


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

    class Result(object):
        def __init__(self):
            self.error = None
            self.value = None

    class CreateZoneResult(object):
        def __init__(self):
            self.inventory = None

    def __init__(self):
        super(CreateZoneAction, self).__init__()
        self.name = None
        self.description = None


