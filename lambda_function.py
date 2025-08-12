import json
import boto3
import uuid
from datetime import datetime
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('FeedbackTable')

def lambda_handler(event, context):
    """
    AWS Lambda handler for processing feedback submissions
    """
    
    # Set CORS headers
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS'
    }
    
    try:
        # Handle preflight OPTIONS request
        if event.get('httpMethod') == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': headers,
                'body': json.dumps({'message': 'CORS preflight successful'})
            }
        
        # Only allow POST requests for feedback submission
        if event.get('httpMethod') != 'POST':
            return {
                'statusCode': 405,
                'headers': headers,
                'body': json.dumps({'error': 'Method not allowed. Use POST.'})
            }
        
        # Parse request body
        if 'body' not in event or not event['body']:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({'error': 'Request body is required'})
            }
        
        # Handle both string and dict body formats
        if isinstance(event['body'], str):
            body = json.loads(event['body'])
        else:
            body = event['body']
        
        # Validate required fields
        required_fields = ['name', 'email', 'message']
        missing_fields = [field for field in required_fields if field not in body or not body[field]]
        
        if missing_fields:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({
                    'error': f'Missing required fields: {", ".join(missing_fields)}'
                })
            }
        
        # Validate email format (basic validation)
        email = body['email']
        if '@' not in email or '.' not in email:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({'error': 'Invalid email format'})
            }
        
        # Validate rating if provided
        rating = body.get('rating')
        if rating is not None:
            try:
                rating = int(rating)
                if rating < 1 or rating > 5:
                    return {
                        'statusCode': 400,
                        'headers': headers,
                        'body': json.dumps({'error': 'Rating must be between 1 and 5'})
                    }
            except (ValueError, TypeError):
                return {
                    'statusCode': 400,
                    'headers': headers,
                    'body': json.dumps({'error': 'Rating must be a number'})
                }
        
        # Prepare feedback data
        feedback_data = {
            'feedback_id': str(uuid.uuid4()),
            'name': body['name'].strip(),
            'email': email.strip().lower(),
            'message': body['message'].strip(),
            'rating': rating,
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')
        }
        
        # Store in DynamoDB
        table.put_item(Item=feedback_data)
        
        # Log successful submission
        logger.info(f"Feedback submitted successfully: {feedback_data['feedback_id']}")
        
        # Return success response
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({
                'message': 'Feedback submitted successfully',
                'feedback_id': feedback_data['feedback_id'],
                'timestamp': feedback_data['timestamp']
            })
        }
        
    except json.JSONDecodeError:
        logger.error("Invalid JSON in request body")
        return {
            'statusCode': 400,
            'headers': headers,
            'body': json.dumps({'error': 'Invalid JSON format'})
        }
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'error': 'Internal server error'})
        }

def get_feedback_handler(event, context):
    """
    Optional: Handler to retrieve feedback (GET request)
    """
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, OPTIONS'
    }
    
    try:
        if event.get('httpMethod') == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': headers,
                'body': json.dumps({'message': 'CORS preflight successful'})
            }
        
        if event.get('httpMethod') != 'GET':
            return {
                'statusCode': 405,
                'headers': headers,
                'body': json.dumps({'error': 'Method not allowed. Use GET.'})
            }
        
        # Scan table for recent feedback (limit to 10 items)
        response = table.scan(Limit=10)
        
        # Sort by timestamp (newest first)
        items = sorted(response['Items'], key=lambda x: x['timestamp'], reverse=True)
        
        # Remove sensitive information
        for item in items:
            item.pop('source_ip', None)
            item.pop('email', None)  # Remove email for privacy
        
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({
                'feedback': items,
                'count': len(items)
            })
        }
        
    except Exception as e:
        logger.error(f"Error retrieving feedback: {str(e)}")
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'error': 'Internal server error'})
        }