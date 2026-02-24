# import logging.config
import structlog
import typing as tp


def get_logger(name: str) -> tp.Any:
    # TODO: setup
    # logging.config.dictConfig(
    #     {
    #         "version": 1,
    #         "disable_existing_loggers": False,
    #         "handlers": {
    #             "default": {
    #                 "level": "DEBUG",
    #                 "class": "logging.StreamHandler",
    #                 "formatter": "colored",
    #             },
    #             "default-file": {
    #                 "level": "INFO",
    #                 "class": "logging.handlers.WatchedFileHandler",
    #                 "filename": "user.log",
    #                 "formatter": "plain",
    #             },
    #             "debug-file": {
    #                 "level": "DEBUG",
    #                 "class": "logging.handlers.WatchedFileHandler",
    #                 "filename": "debug.log",
    #                 "formatter": "plain",
    #             },
    #         },
    #         "loggers": {
    #             "": {
    #                 "handlers": ["default", "default-file", "debug-file"],
    #                 "level": "DEBUG",
    #                 "propagate": True,
    #             },
    #         },
    #     }
    # )
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    return structlog.get_logger(name)
