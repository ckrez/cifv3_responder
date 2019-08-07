#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from cifsdk.client.http import HTTP as Client
from csirtg_indicator import Indicator
from csirtg_indicator.exceptions import InvalidIndicator
from datetime import datetime

class CIFv3(Responder):

    def __init__(self):
        Responder.__init__(self)
        self.remote = self.get_param('config.remote', None, 'Missing CIF remote')
        self.token = self.get_param('config.token', None, 'Missing CIF token')
        self.d_confidence = self.get_param('config.confidence')
        self.verify_ssl = self.get_param('config.verify_ssl')
        self.group = self.get_param('config.group')

        self.TLP_MAP = {
            0: 'WHITE',
            1: 'GREEN',
            2: 'AMBER',
            3: 'RED'
        }

    def run(self):
        Responder.run(self)
        confidence = None

        indicators = []

        # case details
        if self.get_param('data._type') == 'case_artifact':
            a = {}
            a['indicator'] = self.get_param('data.data', None, 'Missing indicator')
            a['tags'] = self.get_param('data.tags')
            a['tlp'] = self.get_param('data.tlp', None)
            a['desc'] = self.get_param('data.message', None)
            a['lasttime'] = self.get_param('data.createdAt', None)
            indicators.append(a)

        # alert details
        if self.get_param('data._type') == 'alert':
            for i in self.get_param('data.artifacts'):
                a = {}
                a['indicator'] = i['data']
                a['tags'] = i['tags']
                a['tlp'] = self.get_param('data.tlp', None)
                a['desc'] = self.get_param('data.description', None)
                a['lasttime'] = self.get_param('data.createdAt', None)
                indicators.append(a)

        for i in indicators:

            # map TLP to word
            tlp = self.TLP_MAP[int(i['tlp'])]

            # confidence tag check
            tags = i['tags']
            for t in tags:
                if 'confidence:' in t:
                    tags.remove(t)
                    (k, v) = t.split(':')
                    confidence = int(v)

            # set to default confidence if not defined
            if not confidence:
                confidence = self.d_confidence

            # convert lasttime
            lasttime = datetime.utcfromtimestamp(i['lasttime']/1000).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            # build indicator
            ii = {
                'indicator': i['indicator'],
                'confidence': confidence,
                'description': i['desc'],
                'tags': tags,
                'tlp': tlp,
                'group': self.group,
                'lasttime': lasttime
            }

            # create indicator object
            try:
                ii = Indicator(**ii)
            except InvalidIndicator as e:
                self.error("Invalid CIF indicator {}".format(e))
            except Exception as e:
                self.error("CIF indicator error: {}".format(e))

            # submit indicator
            cli = Client(token=self.token, remote=self.remote, verify_ssl=self.verify_ssl)

            try:
                r = cli.indicators_create(ii)
            except Exception as e:
                self.error("CIF submission error: {}".format(e))

        self.report({'message': '{} indicator(s) submitted to CIFv3'.format(len(indicators))})

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='cifv3:submitted')]


if __name__ == '__main__':
    CIFv3().run()