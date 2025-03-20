import requests
import random
import time
import logging
from faker import Faker
import os
import argparse
import re
import sys

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource

# Updated logging imports for latest stable API
from opentelemetry import _logs
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter

def parse_size(size_str):
    """Parse human-readable size string to bytes"""
    size_str = size_str.upper().strip()
    
    # Define suffixes and their multipliers
    suffixes = {
        'B': 1,
        '': 1,
        'K': 1024,
        'KB': 1024,
        'M': 1024 * 1024,
        'MB': 1024 * 1024,
        'G': 1024 * 1024 * 1024,
        'GB': 1024 * 1024 * 1024,
        'T': 1024 * 1024 * 1024 * 1024,
        'TB': 1024 * 1024 * 1024 * 1024,
    }
    
    # Match the pattern: number followed by an optional suffix
    match = re.match(r'^(\d+\.?\d*)([KMGTB]B?)?$', size_str)
    if not match:
        raise ValueError(f"Invalid size format: {size_str}")
    
    number, suffix = match.groups()
    suffix = suffix or ''
    
    if suffix not in suffixes:
        raise ValueError(f"Unknown size suffix: {suffix}")
    
    return float(number) * suffixes[suffix]

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='OpenTelemetry log generator')
    parser.add_argument('--otel-endpoint', 
                        type=str, 
                        default='localhost:4317',
                        help='OpenTelemetry collector endpoint (default: localhost:4317)')
    parser.add_argument('--log-size', 
                        type=str, 
                        default='1MB',
                        help='Total amount of logs to generate (e.g., 10KB, 1MB, 2GB)')
    
    return parser.parse_args()

# Function to configure OpenTelemetry with the provided endpoint
def configure_opentelemetry(endpoint):
    """Configure OpenTelemetry with the specified endpoint"""
    resource = Resource(attributes={
        SERVICE_NAME: "wiki-log-generator"
    })
    
    # Set up tracing
    trace_provider = TracerProvider(resource=resource)
    trace_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
    trace_processor = BatchSpanProcessor(trace_exporter)
    trace_provider.add_span_processor(trace_processor)
    trace.set_tracer_provider(trace_provider)
    
    # Set up logging with stable API
    log_provider = LoggerProvider(resource=resource)
    log_exporter = OTLPLogExporter(endpoint=endpoint, insecure=True)
    log_processor = BatchLogRecordProcessor(log_exporter)
    log_provider.add_log_record_processor(log_processor)
    _logs.set_logger_provider(log_provider)
    
    # Configure logger
    logger = logging.getLogger("wiki-log-generator")
    logger.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    logger.addHandler(console_handler)
    
    # OpenTelemetry logging handler - this sends logs to the collector
    otel_handler = LoggingHandler(logger_provider=log_provider)
    logger.addHandler(otel_handler)
    
    return logger

# Initialize Faker for domain generation
faker = Faker()

def get_random_wiki_article():
    """Fetch a random article from Wikipedia with full content"""
    try:
        # First get a random article title
        response = requests.get("https://en.wikipedia.org/api/rest_v1/page/random/summary")
        if response.status_code != 200:
            logger.error(f"Failed to fetch random article: HTTP {response.status_code}")
            return None
        
        article_data = response.json()
        title = article_data.get("title")
        
        # Now fetch the full content of this article
        content_response = requests.get(
            f"https://en.wikipedia.org/w/api.php",
            params={
                "action": "query",
                "format": "json",
                "titles": title,
                "prop": "extracts",
                "explaintext": True,  # Get plain text content
                "formatversion": 2
            }
        )
        
        if content_response.status_code != 200:
            logger.error(f"Failed to fetch article content: HTTP {content_response.status_code}")
            return article_data  # Return summary as fallback
        
        content_data = content_response.json()
        pages = content_data.get("query", {}).get("pages", [])
        
        if pages and len(pages) > 0:
            full_text = pages[0].get("extract", "")
            # Add the full text to our article data
            article_data["full_text"] = full_text
            
        return article_data
    except Exception as e:
        logger.error(f"Error fetching Wikipedia article: {str(e)}")
        return None

def get_random_text_slice(text, length=100):
    """Extract a random slice of text of approximately the specified length"""
    if not text or len(text) <= length:
        return text
    
    # Find a valid starting position
    max_start = len(text) - length
    start = random.randint(0, max_start)
    
    # Try to find a good starting boundary (whitespace)
    for i in range(start, min(start + 20, max_start)):
        if text[i].isspace():
            start = i + 1
            break
    
    # Get the slice
    end = start + length
    
    # Try to find a good ending boundary (period, exclamation, question mark, etc.)
    for i in range(end, min(end + 30, len(text))):
        if text[i] in '.!?':
            end = i + 1
            break
    
    return text[start:end].strip()

def generate_domain_name():
    """Generate a random domain name"""
    return faker.domain_name()

def generate_log_entry(article):
    """Generate a log message using random article slice"""
    log_types = ["INFO", "DEBUG", "WARNING", "ERROR"]
    log_weight = [0.6, 0.2, 0.15, 0.05]  # Weight distribution for log levels
    
    log_level = random.choices(log_types, weights=log_weight)[0]
    
    # Get full text or fallback to extract
    full_text = article.get("full_text", article.get("extract", ""))
    
    # Generate a random slice of the text
    text_slice = get_random_text_slice(full_text, length=100)
    
    return log_level, text_slice

def simulate_logs(target_size_bytes, interval_min=1, interval_max=5, logger=None):
    """Main log generation loop, stopping after generating target_size_bytes"""
    tracer = trace.get_tracer(__name__)
    total_bytes_generated = 0
    
    try:
        logger.info(f"Will generate approximately {target_size_bytes:,} bytes of logs")
        
        # Fetch a single Wikipedia article to use for all logs
        logger.info("Fetching a Wikipedia article to use for all logs...")
        article = get_random_wiki_article()
        
        if not article:
            logger.error("Failed to fetch Wikipedia article. Exiting.")
            return
            
        logger.info(f"Using article: '{article.get('title')}' for log generation")
        
        while total_bytes_generated < target_size_bytes:
            # Generate domain name for this log
            domain = generate_domain_name()
            
            # Create and send log with random text slice
            log_level, text_slice = generate_log_entry(article)
            
            # Track the size of the log message
            message_size = len(text_slice)
            
            # Create a span for this log entry with domain and article attributes
            # All these attributes will be automatically associated with logs
            span_attributes = {
                "domain": domain,
                "article_id": article.get("pageid"),
                "article_title": article.get("title")
            }
            
            with tracer.start_as_current_span("log_entry", attributes=span_attributes):
                # Send log with appropriate level
                if log_level == "INFO":
                    logger.info(text_slice)
                elif log_level == "DEBUG":
                    logger.debug(text_slice)
                elif log_level == "WARNING":
                    logger.warning(text_slice)
                elif log_level == "ERROR":
                    logger.error(text_slice)
                
                total_bytes_generated += message_size
            
            # Progress update for large log generations (every ~10%)
            if target_size_bytes > 1024*1024 and total_bytes_generated % (target_size_bytes // 10) < 1000:
                percent = (total_bytes_generated / target_size_bytes) * 100
                logger.info(f"Progress: {percent:.1f}% ({total_bytes_generated:,} / {target_size_bytes:,} bytes)")
            
            # Wait random time before next log
            time.sleep(random.uniform(interval_min, interval_max))
                
        logger.info(f"Log generation complete. Total bytes generated: {total_bytes_generated:,}")
    except KeyboardInterrupt:
        logger.info(f"Log generation stopped by user. Generated {total_bytes_generated:,} bytes so far.")

if __name__ == "__main__":
    # Parse arguments
    args = parse_arguments()
    
    try:
        # Parse the target log size
        target_size = parse_size(args.log_size)
        
        # Set up OpenTelemetry with the provided endpoint
        logger = configure_opentelemetry(args.otel_endpoint)
        
        logger.info(f"Starting OpenTelemetry log simulator with endpoint: {args.otel_endpoint}")
        logger.info(f"Target log size: {args.log_size} ({target_size:,} bytes)")
        
        # Start the log simulation
        simulate_logs(target_size, interval_min=0.5, interval_max=3, logger=logger)
        
    except ValueError as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)
