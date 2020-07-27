''' Health (PHD) Event Alerts  '''
import os
import json
import boto3
# Health constant Health is configured in us-east-1 in aws.
REGION = 'us-east-1'

HEALTH = boto3.client('health', region_name=REGION)
SNS = boto3.client('sns')

def get_describe_event(event_status_codes):
    ''' Function for describe_events '''
    response = HEALTH.describe_events(
        filter={
            'eventStatusCodes': event_status_codes
        }
    )

    return response

def get_describe_affected_entities(event_arns):
    ''' Function for describe_affected_entities '''
    response = HEALTH.describe_affected_entities(
        filter={
            'eventArns': event_arns
        }
    )

    return response


def handler(event, context):
    ''' Health Lambda Handler '''

    event_status_codes = ['open', 'upcoming']
    result = get_describe_event(event_status_codes)

    # Get describe event details
    event_arns = []
    for event in result['events']:
        event_arns.append(event['arn'])

    # Get describe affected entities
    result = get_describe_affected_entities(event_arns)
    print("starting describe affected entities")
    for entity in result['entities']:
        eventarn = entity['eventArn']
        arn = eventarn.split("/")
        event = arn[2]
        try:
            if entity['statusCode']:
                SNS.publish(
                    TargetArn=os.environ['SNS_TOPIC'],
                    Subject='Health Alerts',
                    Message=json.dumps({
                        'default': 'Health Events are triggered for this event  {} impacting this resource {}'.format(
                            event, entity['entityValue'])
                    }),
                    MessageStructure='json'
                )

                print("Health Events are triggered for this event", event, "impacting this resource", entity['entityValue'], "check Health dashboard(PHD) for more details")
        except KeyError:
            print(entity)
