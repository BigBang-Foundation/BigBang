#!/usr/bin/env python3

# -*- coding: utf-8 -*-

import os
import sys
import re
import codecs

pattern = r'[\u4e00-\u9fff]+|[\uff01-\uff5e]+'


def check_files(path):
    for fpathe, dirs, fs in os.walk(path):
        for f in fs:
            file = os.path.join(fpathe, f)
            print(file)
            with codecs.open(file, 'r', encoding='utf8') as fd:
                content = fd.read()
            if re.search(pattern, content):
                print(re.search(pattern, content))
                return False
            else:
                continue
    return True


def main():
    if not check_files(sys.argv[1]):
        print('finded chinese char')
        sys.exit(1)
    else:
        print('correct encode')
        sys.exit(0)


if __name__ == '__main__':
    main()