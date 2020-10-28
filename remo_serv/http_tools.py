#  Copyright (c) 2020 SBA- MIT License

import http.client


def build_status(code):
    status = http.HTTPStatus(code)
    return '{:3d} {}'.format(code, status.phrase)
