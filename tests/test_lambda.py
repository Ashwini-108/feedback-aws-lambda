import json
import pytest
from unittest.mock import patch, MagicMock
import sys
import os

# Mock boto3 before importing lambda_function
sys.modules['boto3'] = MagicMock()

# Add the parent directory to sys.path to import lambda_function
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock the DynamoDB resource during import
with patch('boto3.resource'):
    from lambda_function import lambda_handler, get_feedback_handler


class TestLambdaHandler:
    
    @patch('lambda_function.table')
    def test_successful_feedback_submission(self, mock_table):
        """Test successful feedback submission"""
        # Mock DynamoDB put_item
        mock_table.put_item.return_value = {}
        
        # Create test event
        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'name': 'John Doe',
                'email': 'john@example.com',
                'message': 'Great service!',
                'rating': 5
            }),
            'requestContext': {
                'identity': {
                    'sourceIp': '192.168.1.1'
                }
            }
        }
        
        # Call the handler
        result = lambda_handler(event, {})
        
        # Assertions
        assert result['statusCode'] == 200
        assert 'message' in json.loads(result['body'])
        assert 'feedback_id' in json.loads(result['body'])
        mock_table.put_item.assert_called_once()
    
    @patch('lambda_function.table')
    def test_missing_required_fields(self, mock_table):
        """Test validation for missing required fields"""
        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'name': 'John Doe',
                'email': 'john@example.com'
                # Missing 'message' field
            })
        }
        
        result = lambda_handler(event, {})
        
        assert result['statusCode'] == 400
        assert 'Missing required fields' in json.loads(result['body'])['error']
        mock_table.put_item.assert_not_called()
    
    @patch('lambda_function.table')
    def test_invalid_email_format(self, mock_table):
        """Test validation for invalid email format"""
        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'name': 'John Doe',
                'email': 'invalid-email',
                'message': 'Test message'
            })
        }
        
        result = lambda_handler(event, {})
        
        assert result['statusCode'] == 400
        assert 'Invalid email format' in json.loads(result['body'])['error']
        mock_table.put_item.assert_not_called()
    
    @patch('lambda_function.table')
    def test_invalid_rating(self, mock_table):
        """Test validation for invalid rating"""
        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'name': 'John Doe',
                'email': 'john@example.com',
                'message': 'Test message',
                'rating': 10  # Invalid rating (should be 1-5)
            })
        }
        
        result = lambda_handler(event, {})
        
        assert result['statusCode'] == 400
        assert 'Rating must be between 1 and 5' in json.loads(result['body'])['error']
        mock_table.put_item.assert_not_called()
    
    @patch('lambda_function.table')
    def test_options_request(self, mock_table):
        """Test CORS preflight OPTIONS request"""
        event = {
            'httpMethod': 'OPTIONS'
        }
        
        result = lambda_handler(event, {})
        
        assert result['statusCode'] == 200
        assert 'Access-Control-Allow-Origin' in result['headers']
        mock_table.put_item.assert_not_called()
    
    @patch('lambda_function.table')
    def test_invalid_http_method(self, mock_table):
        """Test invalid HTTP method"""
        event = {
            'httpMethod': 'GET',
            'body': json.dumps({
                'name': 'John Doe',
                'email': 'john@example.com',
                'message': 'Test message'
            })
        }
        
        result = lambda_handler(event, {})
        
        assert result['statusCode'] == 405
        assert 'Method not allowed' in json.loads(result['body'])['error']
        mock_table.put_item.assert_not_called()
    
    @patch('lambda_function.table')
    def test_empty_request_body(self, mock_table):
        """Test empty request body"""
        event = {
            'httpMethod': 'POST',
            'body': ''
        }
        
        result = lambda_handler(event, {})
        
        assert result['statusCode'] == 400
        assert 'Request body is required' in json.loads(result['body'])['error']
        mock_table.put_item.assert_not_called()
    
    @patch('lambda_function.table')
    def test_invalid_json_body(self, mock_table):
        """Test invalid JSON in request body"""
        event = {
            'httpMethod': 'POST',
            'body': 'invalid json'
        }
        
        result = lambda_handler(event, {})
        
        assert result['statusCode'] == 400
        assert 'Invalid JSON format' in json.loads(result['body'])['error']
        mock_table.put_item.assert_not_called()
    
    @patch('lambda_function.table')
    def test_dynamodb_error(self, mock_table):
        """Test DynamoDB error handling"""
        # Mock DynamoDB to raise an exception
        mock_table.put_item.side_effect = Exception("DynamoDB error")
        
        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'name': 'John Doe',
                'email': 'john@example.com',
                'message': 'Test message'
            })
        }
        
        result = lambda_handler(event, {})
        
        assert result['statusCode'] == 500
        assert 'Internal server error' in json.loads(result['body'])['error']


class TestGetFeedbackHandler:
    
    @patch('lambda_function.table')
    def test_successful_feedback_retrieval(self, mock_table):
        """Test successful feedback retrieval"""
        # Mock DynamoDB scan response
        mock_table.scan.return_value = {
            'Items': [
                {
                    'feedback_id': '123',
                    'name': 'John Doe',
                    'message': 'Great service!',
                    'rating': 5,
                    'timestamp': '2024-01-01T00:00:00',
                    'email': 'john@example.com',
                    'source_ip': '192.168.1.1'
                }
            ]
        }
        
        event = {
            'httpMethod': 'GET'
        }
        
        result = get_feedback_handler(event, {})
        
        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert 'feedback' in body
        assert len(body['feedback']) == 1
        # Ensure sensitive data is removed
        assert 'email' not in body['feedback'][0]
        assert 'source_ip' not in body['feedback'][0]
        mock_table.scan.assert_called_once()
    
    @patch('lambda_function.table')
    def test_get_feedback_invalid_method(self, mock_table):
        """Test invalid HTTP method for get feedback"""
        event = {
            'httpMethod': 'POST'
        }
        
        result = get_feedback_handler(event, {})
        
        assert result['statusCode'] == 405
        assert 'Method not allowed' in json.loads(result['body'])['error']
        mock_table.scan.assert_not_called()