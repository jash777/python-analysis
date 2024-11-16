from typing import Dict, Any, Optional, Tuple
import ollama
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import logging
from functools import lru_cache
import hashlib
import json
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class BaseAgent:
    """Base agent class with common functionality"""
    def __init__(self):
        # Force localhost instead of 0.0.0.0
        self.host = "http://127.0.0.1:11435"  # Hardcode for now to fix the issue
        
        # Change default model to llama3.2
        self.model = os.getenv("OLLAMA_MODEL", "llama3.2")  # Updated to match your installed model
        self.timeout = int(os.getenv("OLLAMA_TIMEOUT", 30))
        self.max_retries = int(os.getenv("MAX_RETRIES", 3))
        
        logger.info(f"Initializing Ollama client with host: {self.host}")
        logger.info(f"Using model: {self.model}")
        
        try:
            self.client = ollama.Client(host=self.host)
            logger.info("Testing connection to Ollama service...")
            self.client.list()
            logger.info("Successfully connected to Ollama service")
        except Exception as e:
            logger.error(f"Failed to initialize Ollama client at {self.host}: {str(e)}")
            logger.error("Please ensure Ollama is running and the host address is correct")
            raise ConnectionError(f"Cannot connect to Ollama service at {self.host}: {str(e)}")

    def _validate_input(self, text: str) -> Tuple[bool, str]:
        """Validate input text"""
        if not text or len(text.strip()) < 10:
            return False, "Input text too short or empty"
        if len(text) > 50000:
            return False, "Input text exceeds maximum length"
        return True, ""

    @lru_cache(maxsize=100)
    def _cached_analysis(self, input_hash: str) -> Optional[str]:
        """Cache analysis results"""
        pass  # Implementation for caching

    def _make_api_call(self, messages: list, options: dict) -> dict:
        """Make API call with enhanced retry logic and error handling"""
        last_error = None
        for attempt in range(self.max_retries):
            try:
                # Add timeout to options
                options['timeout'] = self.timeout
                
                # Log attempt
                logger.debug(f"API call attempt {attempt + 1}/{self.max_retries}")
                
                # Make the API call
                response = self.client.chat(
                    model=self.model,
                    messages=messages,
                    options=options
                )
                
                # Validate response
                if not response or 'message' not in response:
                    raise ValueError("Invalid response from API")
                
                return response

            except ConnectionError as e:
                last_error = f"Connection error (attempt {attempt + 1}): {str(e)}"
                logger.error(last_error)
                # Short delay before retry
                time.sleep(1)
            except Exception as e:
                last_error = f"API error (attempt {attempt + 1}): {str(e)}"
                logger.error(last_error)
                time.sleep(1)

        # If we get here, all retries failed
        raise Exception(f"All API call attempts failed. Last error: {last_error}")

class LogAnalysisAgent(BaseAgent):
    """Enhanced log analysis agent with advanced firewall analysis capabilities"""
    def analyze_raw_logs(self, logs: str) -> str:
        valid, error = self._validate_input(logs)
        if not valid:
            return f"Validation error: {error}"

        try:
            # Hash input for caching
            input_hash = hashlib.md5(logs.encode()).hexdigest()
            cached_result = self._cached_analysis(input_hash)
            if cached_result:
                return cached_result

            prompt = f"""
            Perform comprehensive firewall log analysis with focus on:
            
            1. TRAFFIC ANALYSIS
               - Connection metrics (source/destination IPs, ports, protocols)
               - Bandwidth utilization patterns
               - Session duration statistics
               - Geographic distribution of traffic
               - Application layer protocols
            
            2. SECURITY EVENTS
               - Port scan detection
               - Brute force attempts
               - Known malware signatures
               - DDoS indicators
               - Policy violations
               - Unauthorized access attempts
               - SSL/TLS inspection alerts
            
            3. THREAT INTELLIGENCE
               - Known malicious IP correlation
               - Suspicious domain analysis
               - Command & Control (C2) patterns
               - Data exfiltration attempts
               - Zero-day exploit indicators
            
            4. COMPLIANCE METRICS
               - Policy compliance status
               - Configuration changes
               - Access control effectiveness
               - Data protection measures
            
            5. RISK ASSESSMENT
               - MITRE ATT&CK mapping
               - CVE correlation
               - Asset vulnerability status
               - Impact analysis (Critical/High/Medium/Low)
               - Threat actor attribution (if possible)
            
            Logs: {logs}

            Format: Detailed JSON with categorized findings and severity scores.
            Include specific timestamps, IPs, and event correlations.
            """

            response = self._make_api_call(
                messages=[{
                    'role': 'system',
                    'content': 'You are an advanced firewall log analyzer with expertise in cybersecurity threat detection.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }],
                options={
                    'temperature': 0.2,  # Lower temperature for more focused analysis
                    'num_predict': 2048  # Increased for more detailed response
                }
            )
            
            return response['message']['content']

        except Exception as e:
            return f"Error in log analysis: {str(e)}"

    def analyze_report_data(self, report: str) -> str:
        try:
            prompt = f"""
            Analyze this firewall report and extract key metrics and patterns:

            1. TRAFFIC METRICS
            - Extract all traffic volumes
            - Connection counts
            - IP frequencies
            - Protocol distributions

            2. SECURITY EVENTS
            - Identify all security incidents
            - Extract risk levels
            - List suspicious activities
            - Note policy violations

            3. APPLICATION DATA
            - List all applications
            - Usage statistics
            - Risk categories
            - Behavioral patterns

            Report to analyze:
            {report}

            Provide detailed analysis with specific numbers and examples.
            """

            response = self._make_api_call(
                messages=[{
                    'role': 'system',
                    'content': 'You are a security analyst extracting metrics from firewall reports.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }]
            )
            
            return response['message']['content']

        except Exception as e:
            return f"Error analyzing report: {str(e)}"

class TrafficAnalysisAgent(BaseAgent):
    """Agent responsible for deep traffic pattern analysis"""
    def analyze_traffic_patterns(self, analysis: str) -> str:
        try:
            prompt = f"""
            Extract key traffic patterns:
            1. Peak volumes and times
            2. Common connection patterns
            3. Protocol distribution
            4. Anomalous behavior

            Analysis: {analysis}

            Format: Short, numbered list with metrics.
            """

            response = self._make_api_call(
                messages=[{
                    'role': 'system',
                    'content': 'You are a traffic analyzer. Be concise and specific.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }],
                options={
                    'temperature': 0.3,
                    'num_predict': 512
                }
            )
            
            return response['message']['content']

        except Exception as e:
            return f"Error in traffic analysis: {str(e)}"

class AnomalyDetectionAgent(BaseAgent):
    """Agent responsible for identifying abnormal patterns"""
    def detect_anomalies(self, analysis: str, traffic_patterns: str) -> str:
        try:
            prompt = f"""
            Identify anomalies in this data:
            1. Traffic spikes and unusual volumes
            2. Abnormal protocols or services
            3. Suspicious connection patterns
            4. Statistical outliers

            Analysis: {analysis}
            Patterns: {traffic_patterns}

            Format: Bullet points with specific metrics.
            """

            response = self._make_api_call(
                messages=[{
                    'role': 'system',
                    'content': 'You are an anomaly detector. Be precise and brief.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }],
                options={
                    'temperature': 0.3,
                    'num_predict': 512
                }
            )
            
            return response['message']['content']
        except Exception as e:
            return f"Error in anomaly detection: {str(e)}"

class ReportGeneratorAgent(BaseAgent):
    """Enhanced report generator with advanced security insights"""
    def generate_report(self, log_analysis: str, traffic_analysis: str, anomalies: str) -> str:
        try:
            prompt = f"""
            Generate a comprehensive security report combining:

            1. EXECUTIVE SUMMARY
               - Critical findings overview
               - Risk level assessment
               - Immediate action items
            
            2. THREAT ANALYSIS
               - Detected attack patterns
               - Malicious activity timeline
               - Affected systems/services
               - MITRE ATT&CK correlation
            
            3. TRAFFIC INSIGHTS
               - Bandwidth utilization
               - Protocol distribution
               - Geographic traffic patterns
               - Application usage statistics
            
            4. SECURITY EVENTS
               - Policy violations
               - Access attempts analysis
               - Malware detection results
               - DDoS activity monitoring
            
            5. COMPLIANCE STATUS
               - Policy adherence metrics
               - Configuration audit results
               - Data protection status
            
            6. DETAILED RECOMMENDATIONS
               - Immediate mitigation steps
               - Long-term security improvements
               - Configuration changes
               - Monitoring enhancements

            7. INCIDENT TIMELINE
               - Chronological event sequence
               - Attack progression analysis
               - Response actions taken

            Input Data:
            Log Analysis: {log_analysis}
            Traffic Patterns: {traffic_analysis}
            Anomalies: {anomalies}

            Format Requirements:
            - Clear section headers
            - Bullet points for key findings
            - Severity ratings for each finding
            - Specific metrics and timestamps
            - Technical details in appendix
            """

            response = self._make_api_call(
                messages=[{
                    'role': 'system',
                    'content': 'You are an expert security analyst specializing in firewall log analysis and threat detection.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }],
                options={
                    'temperature': 0.3,
                    'num_predict': 2048
                }
            )
            
            return response['message']['content']
        except Exception as e:
            return f"Error in report generation: {str(e)}"

class SecurityAIAgent:
    """Enhanced main agent with improved coordination"""
    def __init__(self):
        self.log_analyzer = LogAnalysisAgent()
        self.traffic_analyzer = TrafficAnalysisAgent()
        self.anomaly_detector = AnomalyDetectionAgent()
        self.report_generator = ReportGeneratorAgent()
        self.analysis_history = []
        
    def _calculate_severity_score(self, anomalies: str) -> int:
        """Calculate overall severity score"""
        # Implementation for severity scoring
        pass

    def analyze_logs(self, raw_logs: str) -> str:
        """Enhanced log analysis pipeline with better error handling"""
        try:
            # Input validation
            valid, error = self.log_analyzer._validate_input(raw_logs)
            if not valid:
                return self.format_enhanced_report(f"Validation error: {error}", 1)

            # Track analysis start time
            start_time = datetime.now()
            
            try:
                # Step 1: Initial log analysis
                log_analysis = self.log_analyzer.analyze_raw_logs(raw_logs)
                
                # Step 2: Traffic pattern analysis
                traffic_analysis = self.traffic_analyzer.analyze_traffic_patterns(log_analysis)
                
                # Step 3: Anomaly detection
                anomalies = self.anomaly_detector.detect_anomalies(log_analysis, traffic_analysis)
                
                # Step 4: Generate final report
                final_report = self.report_generator.generate_report(
                    log_analysis=log_analysis,
                    traffic_analysis=traffic_analysis,
                    anomalies=anomalies
                )

                # Calculate severity score
                severity_score = self._calculate_basic_severity(anomalies)

                # Store analysis history
                self.analysis_history.append({
                    "timestamp": start_time,
                    "duration": (datetime.now() - start_time).total_seconds(),
                    "severity_score": severity_score
                })

                return self.format_enhanced_report(final_report, severity_score)

            except ConnectionError as e:
                error_msg = f"Connection to AI service failed: {str(e)}\nPlease check if Ollama service is running correctly."
                logger.error(error_msg)
                return self.format_enhanced_report(error_msg, 1)
                
            except Exception as e:
                error_msg = f"Analysis error: {str(e)}"
                logger.error(error_msg)
                return self.format_enhanced_report(error_msg, 1)

        except Exception as e:
            error_msg = f"Critical pipeline error: {str(e)}"
            logger.error(error_msg)
            return self.format_enhanced_report(error_msg, 1)

    def format_enhanced_report(self, report_content: str, severity_score: int) -> str:
        """Format the final report with enhanced styling and details"""
        if report_content is None:
            report_content = "No analysis results available"
        if severity_score is None:
            severity_score = 1

        severity_description = {
            1: "Low - Regular monitoring recommended",
            2: "Moderate-Low - Enhanced monitoring needed",
            3: "Moderate - Immediate investigation required",
            4: "High - Urgent attention needed - Potential breach",
            5: "Critical - Immediate response required - Active threat"
        }.get(severity_score, "Unknown")

        current_time = datetime.now()
        
        return f"""
{'='*65}
                FIREWALL LOG ANALYSIS - AI INSIGHTS
{'='*65}
Report ID: SEC_{current_time.strftime('%Y%m%d_%H%M%S')}
Analysis Date: {current_time.strftime('%Y-%m-%d %H:%M:%S')}
Analysis Method: Advanced Multi-Agent AI Security Analysis System
{'-'*65}

{report_content}

{'='*65}
RISK ASSESSMENT
{'='*65}
Severity Score: {severity_score} - {severity_description}
Analysis Duration: {self.analysis_history[-1]['duration']:.2f} seconds
Threat Level: {self._get_threat_level(severity_score)}

{'='*65}
ANALYSIS METRICS
{'='*65}
- Processing Time: {self.analysis_history[-1]['duration']:.2f} seconds
- AI Model: {self.log_analyzer.model}
- Analysis Depth: Comprehensive
- Pattern Recognition: Advanced
- Threat Intelligence: Integrated

{'='*65}
                    END OF AI ANALYSIS
{'='*65}

╔{'═'*62}╗
║{' '*62}║
║{' '*15}Powered by AlphaSec™ Advanced Security{' '*15}║
║{' '*12}AI-Driven Firewall Analytics Platform{' '*12}║
║{' '*62}║
╚{'═'*62}╝
"""

    def _get_threat_level(self, severity_score: int) -> str:
        """Generate detailed threat level description"""
        threat_levels = {
            1: "INFORMATIONAL - Normal network activity with no significant security concerns",
            2: "ELEVATED - Minor security concerns detected, monitoring recommended",
            3: "WARNING - Notable security events detected, investigation required",
            4: "CRITICAL - Serious security threats detected, immediate action needed",
            5: "EMERGENCY - Severe security breach in progress, immediate response required"
        }
        return threat_levels.get(severity_score, "UNKNOWN - Threat level could not be determined")

    def _calculate_basic_severity(self, anomalies: str) -> int:
        """Basic severity scoring implementation"""
        try:
            # Count critical keywords
            critical_keywords = ['critical', 'high', 'severe', 'attack', 'breach', 'malware']
            warning_keywords = ['warning', 'suspicious', 'unusual', 'failed']
            
            anomalies_lower = anomalies.lower()
            critical_count = sum(anomalies_lower.count(keyword) for keyword in critical_keywords)
            warning_count = sum(anomalies_lower.count(keyword) for keyword in warning_keywords)
            
            # Calculate score (1-5 scale)
            if critical_count > 5:
                return 5
            elif critical_count > 3 or (critical_count > 1 and warning_count > 3):
                return 4
            elif critical_count > 0 or warning_count > 3:
                return 3
            elif warning_count > 0:
                return 2
            return 1
            
        except Exception as e:
            logger.error(f"Error calculating severity: {str(e)}")
            return 3  # Default moderate severity on error
