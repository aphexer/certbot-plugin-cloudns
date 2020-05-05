import logging

from certbot import interfaces

# import zope.component
import zope.interface

from certbot.plugins import dns_common
import certbot.errors
import cloudns_api
import time

ACCOUNT_URL = 'https://www.cloudns.net/api-settings/'

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    description = 'Obtain certificates using a DNS TXT record (if you are using ClouDNS for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.records = {}

    @classmethod
    def add_parser_arguments(cls, add): # pylint: disable=missing-docstring
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=0)
        add('credentials', help='ClouDNS credentials INI file.')
        add('aliasdomain', help='Use this DNS zone to create the _acme-challenge record in, instead of the provided zone')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the ClouDNS API.'

    def _setup_credentials(self):
        def validator(config):
            if(not config._has('auth-id') and not config._has('sub-auth-id')):
                raise certbot.errors.PluginError('You must specify either auth-id or sub-auth-id in the ClouDNS credentials INI file')

        self.credentials = self._configure_credentials(
            'credentials',
            'ClouDNS credentials INI file',
            {
                'password': 'Password for CloudDNS api user, obtained from {0}'.format(ACCOUNT_URL)
            },
            validator
        )

    def _searchZoneForDomain(self, zones, domain):
        match = {'name': ''}
        for zone in zones:
            if zone['zone'] != 'domain':
                continue
            pos = domain.find(zone['name'])
            logger.debug("Trying to match zone: %s", repr(zone))
            if pos != -1:
                # this is the zone
                logger.debug("Got a match: {}".format(repr(zone)))
                if match['name']:
                    if match['priority'] > pos:
                        match = {'name': zone['name'], 'priority': pos}
                else:
                    match = {'name': zone['name'], 'priority': pos}
        if not match['name']:
            return False
        zonename = match['name']
        logger.debug("Matched domain name: %s", zonename)
        return zonename

    def _perform(self, domain, validation_name, validation):

        logger.debug("Creating dns txt record for domain " + domain + " with validation " + validation + ", validation_name: " + validation_name)
        aliasdomain = self.conf('aliasdomain')
        logger.debug("alias config: " + str(aliasdomain))
        self._setup_cloudns_credentials()
        
        # Find ClouDNS zone to use
        zones = cloudns_api.zone.list()
        js = zones.json()
        if(aliasdomain):
            zonename = aliasdomain
            recordname = validation_name.replace(domain, '')[:-1]
        else:
            zonename = self._searchZoneForDomain(zones, domain)
            recordname = validation_name.replace(zonename, '')[:-1]
    
        logger.debug("Record: %s", recordname)

        # First delete existing records if they exist
        logger.debug("Deleting existing TXT records at " + recordname + "." + zonename)
        response = cloudns_api.record.list(domain_name=zonename, host=recordname, record_type='TXT')
        response_json = response.json()
        if response.status_code != 200 or response_json is None:
            raise certbot.errors.PluginError('Could not list records in ClouDNS, response code: ' + response.status_code + ", message: " + str(response_json))
        response_data = response_json['payload']
        logger.debug("Existing records: " + str(response_data))
        for record_id in response_data.keys():
            logger.debug("record_id: " + record_id)
            logger.debug("Deleting record " + record_id)
            response = cloudns_api.record.delete(zonename, record_id)
            if response.status_code != 200:
                raise certbot.errors.PluginError('Could not delete record ' + record_id + ', statuscode: ' + response.status_code)

        # Create record with the validation
        logger.debug("Creating TXT record for " + recordname + "." + zonename)
        response = cloudns_api.record.create(domain_name=zonename,
                                                         host=recordname, record_type='TXT',
                                                         record=validation, ttl=60)

        logger.debug("ClouDNS response: " + str(response.json()))
        response_json = response.json()
        if response.status_code != 200 or response_json is None:
            raise certbot.errors.PluginError('Could not create record in ClouDNS, response code: ' + response.status_code + ", message: " + str(response_json))

        if 'payload' not in response_json:
            raise certbot.errors.PluginError('Error: payload is not present in ClouDNS response. Response was: ' + response_json)
        response_data = response_json['payload']

        if 'data' not in response_data or 'id' not in response_data['data']:
            raise certbot.errors.PluginError('Error: response did not contain data[id] field. Response was: ' + response_json)

        self.records[validation_name] = {'id': response_data['data']['id'], 'zone': zonename}

        updated = False
        while(updated == False):
            response = cloudns_api.zone.isupdated(domain_name=aliasdomain)
            r = response.json()
            updated = r['payload']
            print("Waiting for all DNS servers to be updated...")
            time.sleep(5)

    def _cleanup(self, domain, validation_name, validation):
        logger.debug("performing cleanup for %s", validation_name)
        logger.debug("Deleting record " + str(self.records[validation_name]['id']) + " from zone " + self.records[validation_name]['zone'])
        response = cloudns_api.record.delete(self.records[validation_name]['zone'], self.records[validation_name]['id'])

    def _setup_cloudns_credentials(self):
        if(self.credentials._has('auth_id')):            
            cloudns_api.config.set_auth_params(auth_id=self.credentials.conf('auth_id'), auth_password=self.credentials.conf('password'))
        if(self.credentials._has('sub_auth_id')):
            cloudns_api.config.set_auth_params(sub_auth_id=self.credentials.conf('sub_auth_id'), auth_password=self.credentials.conf('password'))
