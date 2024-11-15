import pandas as pd
import numpy as np
from collections import Counter, defaultdict
from datetime import datetime
import ipaddress
from typing import Dict, List, Any, Optional, Union
from functools import lru_cache
import json
import logging
from pathlib import Path
import re

class FortiGateLogAnalyzer:
    def __init__(self, logs: Union[str, Path], cache_enabled: bool = True):
        """
        Initialize the analyzer with logs from string or file path
        
        Args:
            logs: Raw log content or path to log file
            cache_enabled: Enable caching for performance optimization
        """
        self.cache_enabled = cache_enabled
        self.logger = self._setup_logging()
        self.raw_logs = self._load_logs(logs)
        self.df = self._parse_logs()
        self.analysis_results = {}
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging for the analyzer"""
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def _load_logs(self, logs: Union[str, Path]) -> str:
        """Load logs from string or file"""
        if isinstance(logs, Path) or (isinstance(logs, str) and Path(logs).exists()):
            try:
                with open(logs, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                self.logger.error(f"Error reading log file: {e}")
                raise
        return logs

    @lru_cache(maxsize=128)
    def _parse_line(self, line: str) -> Dict[str, Any]:
        """Parse single log line with caching"""
        record = {}
        try:
            # Enhanced parsing with regex to handle complex values
            pattern = r'(\w+)=((?:[^=]|==)+?)(?=\s+\w+=|$)'
            matches = re.finditer(pattern, line)
            for match in matches:
                key, value = match.groups()
                value = value.strip('"')
                record[key] = value
        except Exception as e:
            self.logger.warning(f"Error parsing line: {line[:50]}... Error: {e}")
        return record

    def _parse_logs(self) -> pd.DataFrame:
        """Parse raw logs into pandas DataFrame with enhanced error handling and format detection"""
        records = []
        for line in self.raw_logs.split('\n'):
            if not line.strip():
                continue
            
            record = self._parse_line(line) if self.cache_enabled else self._parse_line.__wrapped__(self, line)
            if record:
                # Add default values for optional fields based on subtype
                if record.get('subtype') == 'local':
                    record.setdefault('apprisk', 'not_applicable')
                    record.setdefault('appcat', 'not_applicable')
                records.append(record)

        if not records:
            raise ValueError("No valid log entries found")

        df = pd.DataFrame(records)
        
        # Enhanced data type conversion with format detection
        self._convert_datatypes(df)
        
        # Add derived columns based on available fields
        self._add_derived_columns(df)
        
        return df

    def _convert_datatypes(self, df: pd.DataFrame) -> None:
        """Convert DataFrame columns to appropriate data types with enhanced robustness"""
        # Convert numeric columns (handle both formats)
        numeric_cols = [
            'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt', 'duration',
            'identifier', 'signal', 'snr', 'channel'
        ]
        
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        
        # Handle timestamp conversion with format detection
        if 'date' in df.columns and 'time' in df.columns:
            try:
                df['timestamp'] = pd.to_datetime(df['date'] + ' ' + df['time'])
            except Exception as e:
                self.logger.warning(f"Error converting timestamp: {e}")
        elif 'eventtime' in df.columns:
            try:
                # Convert nanosecond timestamps
                df['timestamp'] = pd.to_datetime(df['eventtime'].astype(float), unit='ns')
            except Exception as e:
                self.logger.warning(f"Error converting eventtime: {e}")

    def _add_derived_columns(self, df: pd.DataFrame) -> None:
        """Add derived columns based on available fields"""
        # Update traffic direction mapping
        if 'subtype' in df.columns:
            df['direction'] = df['subtype'].map({
                'forward': 'forwarded',
                'local': 'local'
            }).fillna('unknown')

        # Add connection type for IPv6/IPv4
        df['ip_version'] = df.apply(lambda row: 
            'IPv6' if any(':' in str(row.get(ip, '')) 
            for ip in ['srcip', 'dstip']) else 'IPv4', axis=1)

        # Add wireless info if available
        wireless_indicators = ['radioband', 'signal', 'ap', 'srcssid']
        df['is_wireless'] = df.apply(
            lambda row: any(row.get(ind) is not None for ind in wireless_indicators), 
            axis=1
        )

    def export_results(self, format: str = 'json', output_path: Optional[Path] = None) -> Optional[str]:
        """
        Export analysis results in various formats
        
        Args:
            format: Output format ('json', 'csv', 'html')
            output_path: Path to save the output file
        """
        if not self.analysis_results:
            self.analyze()

        if format == 'json':
            output = json.dumps(self.analysis_results, indent=2)
        elif format == 'csv':
            output = pd.DataFrame(self.analysis_results).to_csv()
        elif format == 'html':
            output = self.generate_html_report()
        else:
            raise ValueError(f"Unsupported format: {format}")

        if output_path:
            output_path = Path(output_path)
            output_path.write_text(output)
            self.logger.info(f"Results exported to {output_path}")
        else:
            return output

    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive analysis and cache results"""
        self.analysis_results = {
            'basic_stats': self._analyze_basic_stats(),
            'security_metrics': self._analyze_security_metrics(),
            'traffic_patterns': self._analyze_traffic_patterns(),
            'anomalies': self._detect_anomalies(),
            'recommendations': self._generate_recommendations(),
            'security_concerns': self._identify_security_concerns()
        }
        return self.analysis_results

    def _analyze_basic_stats(self) -> Dict[str, Any]:
        """Analyze basic statistics with field validation"""
        stats = {'total_records': len(self.df)}
        
        # Add metrics only if fields exist
        if 'srcip' in self.df.columns:
            stats['unique_sources'] = self.df['srcip'].nunique()
        if 'dstip' in self.df.columns:
            stats['unique_destinations'] = self.df['dstip'].nunique()
        if all(field in self.df.columns for field in ['sentbyte', 'rcvdbyte']):
            stats['total_traffic'] = self._format_bytes(
                self.df['sentbyte'].sum() + self.df['rcvdbyte'].sum()
            )
        return stats

    def _analyze_security_metrics(self) -> Dict[str, Any]:
        """Analyze security-related metrics with support for both traffic types"""
        metrics = {}
        
        try:
            # Split analysis by traffic subtype
            for subtype in ['forward', 'local']:
                try:
                    subtype_df = self.df[self.df['subtype'] == subtype]
                    if not subtype_df.empty:
                        metrics[f'{subtype}_metrics'] = {}
                        
                        # Basic metrics (always present)
                        metrics[f'{subtype}_metrics']['total_connections'] = len(subtype_df)
                        
                        # Action-based metrics
                        if 'action' in subtype_df.columns:
                            actions = subtype_df['action'].value_counts()
                            metrics[f'{subtype}_metrics']['actions'] = actions.to_dict()
                        
                        # Traffic volume metrics
                        if all(col in subtype_df.columns for col in ['sentbyte', 'rcvdbyte']):
                            total_bytes = subtype_df['sentbyte'].sum() + subtype_df['rcvdbyte'].sum()
                            metrics[f'{subtype}_metrics']['total_traffic'] = self._format_bytes(total_bytes)
                        
                        # Subtype-specific metrics
                        if subtype == 'forward':
                            # Only process apprisk for forward traffic
                            if 'apprisk' in subtype_df.columns and subtype_df['apprisk'].notna().any():
                                try:
                                    metrics[f'{subtype}_metrics']['risk_levels'] = (
                                        subtype_df['apprisk'].value_counts().to_dict()
                                    )
                                except Exception as e:
                                    self.logger.warning(f"Error processing apprisk for forward traffic: {str(e)}")
                            
                            # Other forward-specific metrics
                            if 'policyname' in subtype_df.columns:
                                metrics[f'{subtype}_metrics']['policies'] = (
                                    subtype_df['policyname'].value_counts().head(10).to_dict()
                                )
                            if 'appcat' in subtype_df.columns:
                                metrics[f'{subtype}_metrics']['app_categories'] = (
                                    subtype_df['appcat'].value_counts().to_dict()
                                )
                        
                        elif subtype == 'local':
                            # Local-specific metrics (no apprisk processing)
                            if 'srcintf' in subtype_df.columns:
                                metrics[f'{subtype}_metrics']['interfaces'] = (
                                    subtype_df['srcintf'].value_counts().to_dict()
                                )
                            if 'dstintf' in subtype_df.columns:
                                metrics[f'{subtype}_metrics']['dst_interfaces'] = (
                                    subtype_df['dstintf'].value_counts().to_dict()
                                )
                        
                        # Wireless metrics if available (for both types)
                        if all(field in subtype_df.columns for field in ['signal', 'radioband']):
                            wireless_df = subtype_df[subtype_df['radioband'].notna()]
                            if not wireless_df.empty:
                                metrics[f'{subtype}_metrics']['wireless'] = {
                                    'total_wireless': len(wireless_df),
                                    'avg_signal': wireless_df['signal'].mean(),
                                    'bands': wireless_df['radioband'].value_counts().to_dict()
                                }
                
                except Exception as e:
                    self.logger.warning(f"Error processing {subtype} traffic metrics: {str(e)}")
                    metrics[f'{subtype}_error'] = str(e)

        except Exception as e:
            self.logger.error(f"Error in security metrics analysis: {str(e)}")
            metrics['error'] = str(e)
        
        return metrics

    def _analyze_traffic_patterns(self) -> Dict[str, Any]:
        """Analyze traffic patterns with enhanced error handling"""
        patterns = {}
        
        try:
            # Separate analysis by traffic subtype
            for subtype in ['forward', 'local']:
                try:
                    subtype_df = self.df[self.df['subtype'] == subtype]
                    if not subtype_df.empty:
                        patterns[f'{subtype}_traffic'] = {
                            'count': len(subtype_df),
                            'percentage': len(subtype_df) / len(self.df) * 100,
                        }

                        # Add traffic volume if available
                        try:
                            if all(col in subtype_df.columns for col in ['sentbyte', 'rcvdbyte']):
                                total_bytes = subtype_df['sentbyte'].sum() + subtype_df['rcvdbyte'].sum()
                                patterns[f'{subtype}_traffic']['volume'] = self._format_bytes(total_bytes)
                        except Exception as e:
                            self.logger.warning(f"Error calculating traffic volume for {subtype}: {str(e)}")

                        # Add specific metrics for each subtype
                        if subtype == 'local':
                            try:
                                if 'srcintf' in subtype_df.columns:
                                    patterns['local_interfaces'] = subtype_df['srcintf'].value_counts().to_dict()
                                if 'action' in subtype_df.columns:
                                    patterns['local_actions'] = subtype_df['action'].value_counts().to_dict()
                            except Exception as e:
                                self.logger.warning(f"Error processing local traffic metrics: {str(e)}")

                        elif subtype == 'forward':
                            try:
                                if 'policyname' in subtype_df.columns:
                                    patterns['forward_policies'] = subtype_df['policyname'].value_counts().to_dict()
                                if 'appcat' in subtype_df.columns:
                                    patterns['forward_app_categories'] = subtype_df['appcat'].value_counts().to_dict()
                                if 'apprisk' in subtype_df.columns:
                                    patterns['forward_risk_levels'] = subtype_df['apprisk'].value_counts().to_dict()
                            except Exception as e:
                                self.logger.warning(f"Error processing forward traffic metrics: {str(e)}")

                except Exception as e:
                    self.logger.warning(f"Error processing {subtype} traffic: {str(e)}")
                    patterns[f'{subtype}_error'] = str(e)

        except Exception as e:
            self.logger.error(f"Error analyzing traffic patterns: {str(e)}")
            patterns['error'] = str(e)
        
        return patterns

    def _detect_anomalies(self) -> Dict[str, Any]:
        """Detect traffic anomalies with enhanced format support"""
        anomalies = {}
        available_fields = set(self.df.columns)
        
        try:
            # Traffic volume anomalies (if available)
            if 'sentbyte' in available_fields:
                self._add_volume_anomalies(anomalies)
            
            # Connection anomalies (always available)
            self._add_connection_anomalies(anomalies)
            
            # Wireless anomalies (if available)
            if all(field in available_fields for field in ['signal', 'ap', 'radioband']):
                self._add_wireless_anomalies(anomalies)
            
            # Policy violations (if available)
            if 'action' in available_fields:
                self._add_policy_violations(anomalies)
            
            # Risk-based anomalies (if available)
            if 'apprisk' in available_fields:
                self._add_risk_anomalies(anomalies)
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {str(e)}")
            anomalies['error'] = str(e)
        
        return anomalies

    def _format_bytes(self, bytes_value: float) -> str:
        """Format bytes into human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024
            
    def generate_text_report(self) -> str:
        """Generate comprehensive text-based report"""
        report = []
        
        # Report Header
        report.extend([
            "="*80,
            "FIREWALL LOG ANALYSIS REPORT",
            "="*80,
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Analysis Period: {self.df['date'].iloc[0]} {self.df['time'].iloc[0]} to {self.df['date'].iloc[-1]} {self.df['time'].iloc[-1]}",
            "="*80,
            ""
        ])

        # 1. Executive Summary
        report.extend([
            "1. EXECUTIVE SUMMARY",
            "-"*80,
            f"Total Records Analyzed: {len(self.df):,}",
            f"Unique Source IPs: {self.df['srcip'].nunique():,}",
            f"Unique Destination IPs: {self.df['dstip'].nunique():,}",
            f"Total Data Transferred: {self._format_bytes(self.df['sentbyte'].sum() + self.df['rcvdbyte'].sum())}",
            ""
        ])

        # 2. Security Analysis
        report.extend([
            "2. SECURITY ANALYSIS",
            "-"*80
        ])
        
        # Action Analysis
        action_counts = self.df['action'].value_counts()
        report.extend([
            "2.1 Traffic Actions:",
            *[f"    {action}: {count:,} ({count/len(self.df)*100:.1f}%)" 
              for action, count in action_counts.items()],
            ""
        ])
        
        # Risk Analysis
        risk_counts = self.df['apprisk'].value_counts()
        report.extend([
            "2.2 Application Risk Distribution:",
            *[f"    {risk}: {count:,} ({count/len(self.df)*100:.1f}%)" 
              for risk, count in risk_counts.items()],
            ""
        ])
        
        # High Risk Applications
        high_risk = self.df[self.df['apprisk'] == 'elevated']
        if not high_risk.empty:
            report.extend([
                "2.3 High Risk Applications Detected:",
                *[f"    - {app}: {count:,} instances" 
                  for app, count in high_risk['app'].value_counts().head(10).items()],
                ""
            ])

        # Add new Denied Traffic Analysis section
        report.extend([
            "2.4 DENIED TRAFFIC ANALYSIS",
            "-"*80
        ])
        
        denied_traffic = self.df[self.df['action'] == 'deny']
        if not denied_traffic.empty:
            # Overall denied traffic statistics
            report.extend([
                f"Total Denied Connections: {len(denied_traffic):,}",
                f"Percentage of Total Traffic: {(len(denied_traffic)/len(self.df)*100):.2f}%",
                f"Total Denied Traffic Volume: {self._format_bytes(denied_traffic['sentbyte'].sum() + denied_traffic['rcvdbyte'].sum())}",
                ""
            ])

            # Top sources of denied traffic
            report.extend([
                "Top Source IPs with Denied Traffic:",
                *[f"    - {ip}: {count:,} attempts ({self._format_bytes(bytes_)})" 
                  for ip, (count, bytes_) in denied_traffic.groupby('srcip').agg({
                      'srcip': 'count',
                      'sentbyte': 'sum'
                  }).sort_values('srcip', ascending=False).head(10).iterrows()],
                ""
            ])

            # Top destinations of denied traffic
            report.extend([
                "Top Destination IPs in Denied Traffic:",
                *[f"    - {ip}: {count:,} attempts ({self._format_bytes(bytes_)})" 
                  for ip, (count, bytes_) in denied_traffic.groupby('dstip').agg({
                      'dstip': 'count',
                      'rcvdbyte': 'sum'
                  }).sort_values('dstip', ascending=False).head(10).iterrows()],
                ""
            ])

            # Denied traffic by service
            report.extend([
                "Services in Denied Traffic:",
                *[f"    - {service}: {count:,} attempts" 
                  for service, count in denied_traffic['service'].value_counts().head(10).items()],
                ""
            ])

            # Denied traffic by application
            report.extend([
                "Applications in Denied Traffic:",
                *[f"    - {app}: {count:,} attempts" 
                  for app, count in denied_traffic['app'].value_counts().head(10).items()],
                ""
            ])

            # Denied traffic by policy
            report.extend([
                "Policies Triggering Denials:",
                *[f"    - {policy}: {count:,} denials" 
                  for policy, count in denied_traffic['policyname'].value_counts().head(10).items()],
                ""
            ])

            # Time-based analysis of denied traffic
            if 'timestamp' in denied_traffic.columns:
                denied_by_hour = denied_traffic.groupby(denied_traffic['timestamp'].dt.hour)['srcip'].count()
                report.extend([
                    "Hourly Distribution of Denied Traffic:",
                    *[f"    - Hour {hour:02d}: {count:,} denials" 
                      for hour, count in denied_by_hour.items()],
                    ""
                ])

            # Geographic analysis of denied traffic
            if 'dstcountry' in denied_traffic.columns:
                report.extend([
                    "Countries Involved in Denied Traffic:",
                    *[f"    - {country}: {count:,} attempts" 
                      for country, count in denied_traffic['dstcountry'].value_counts().head(10).items()],
                    ""
                ])

            # Risk level analysis of denied traffic
            if 'apprisk' in denied_traffic.columns:
                report.extend([
                    "Risk Levels in Denied Traffic:",
                    *[f"    - {risk}: {count:,} attempts" 
                      for risk, count in denied_traffic['apprisk'].value_counts().items()],
                    ""
                ])

        else:
            report.extend([
                "No denied traffic found in the logs.",
                ""
            ])

        # 3. Traffic Analysis
        report.extend([
            "3. TRAFFIC ANALYSIS",
            "-"*80
        ])
        
        # Top Talkers (Source IPs)
        top_sources = self.df.groupby('srcip')['sentbyte'].sum().sort_values(ascending=False).head(10)
        report.extend([
            "3.1 Top Source IPs by Traffic Volume:",
            *[f"    {ip}: {self._format_bytes(bytes_)}" 
              for ip, bytes_ in top_sources.items()],
            ""
        ])
        
        # Top Destinations
        top_dests = self.df.groupby('dstip')['rcvdbyte'].sum().sort_values(ascending=False).head(10)
        report.extend([
            "3.2 Top Destination IPs by Traffic Volume:",
            *[f"    {ip}: {self._format_bytes(bytes_)}" 
              for ip, bytes_ in top_dests.items()],
            ""
        ])
        
        # Service Analysis
        service_counts = self.df['service'].value_counts().head(10)
        report.extend([
            "3.3 Top Services:",
            *[f"    {service}: {count:,} connections" 
              for service, count in service_counts.items()],
            ""
        ])

        # 4. Geographic Analysis
        report.extend([
            "4. GEOGRAPHIC ANALYSIS",
            "-"*80,
            "4.1 Top Destination Countries:",
            *[f"    {country}: {count:,} connections" 
              for country, count in self.df['dstcountry'].value_counts().head(10).items()],
            ""
        ])

        # 5. Application Analysis
        report.extend([
            "5. APPLICATION ANALYSIS",
            "-"*80
        ])
        
        # Application Categories
        app_cats = self.df['appcat'].value_counts()
        report.extend([
            "5.1 Application Categories:",
            *[f"    {cat}: {count:,} ({count/len(self.df)*100:.1f}%)" 
              for cat, count in app_cats.items()],
            ""
        ])
        
        # Enhanced Top Applications with IP details
        top_apps = self.df['app'].value_counts().head(10)
        report.extend([
            "5.2 Top Applications:",
            *[f"    {app}: {count:,} connections" 
              for app, count in top_apps.items()],
            ""
        ])
        
        # Add detailed analysis for each top application
        report.extend([
            "5.3 Detailed Application Analysis:",
            "-"*40
        ])
        
        for app in top_apps.index:
            app_data = self.df[self.df['app'] == app]
            report.extend([
                f"\nApplication: {app}",
                f"Total Traffic: {self._format_bytes(app_data['sentbyte'].sum() + app_data['rcvdbyte'].sum())}",
                "Top Source IPs:",
                *[f"    - {ip}: {count:,} connections ({self._format_bytes(bytes_)})" 
                  for ip, (count, bytes_) in app_data.groupby('srcip').agg({
                      'srcip': 'count', 
                      'sentbyte': 'sum'
                  }).head(5).iterrows()],
                "Top Destination IPs:",
                *[f"    - {ip}: {count:,} connections ({self._format_bytes(bytes_)})" 
                  for ip, (count, bytes_) in app_data.groupby('dstip').agg({
                      'dstip': 'count', 
                      'rcvdbyte': 'sum'
                  }).head(5).iterrows()],
                ""
            ])

        # Enhanced Policy Analysis
        report.extend([
            "6. POLICY ANALYSIS",
            "-"*80,
            "6.1 Policy Usage:",
            *[f"    {policy}: {count:,} hits" 
              for policy, count in self.df['policyname'].value_counts().head(10).items()],
            ""
        ])
        
        # Add detailed analysis for each top policy
        report.extend([
            "6.2 Detailed Policy Analysis:",
            "-"*40
        ])
        
        top_policies = self.df['policyname'].value_counts().head(5)
        for policy in top_policies.index:
            policy_data = self.df[self.df['policyname'] == policy]
            report.extend([
                f"\nPolicy: {policy}",
                f"Total Traffic: {self._format_bytes(policy_data['sentbyte'].sum() + policy_data['rcvdbyte'].sum())}",
                "Most Active Source IPs:",
                *[f"    - {ip}: {count:,} hits ({self._format_bytes(bytes_)})" 
                  for ip, (count, bytes_) in policy_data.groupby('srcip').agg({
                      'srcip': 'count', 
                      'sentbyte': 'sum'
                  }).head(5).iterrows()],
                "Most Accessed Applications:",
                *[f"    - {app}: {count:,} times" 
                  for app, count in policy_data['app'].value_counts().head(5).items()],
                "Traffic by Risk Level:",
                *[f"    - {risk}: {count:,} connections" 
                  for risk, count in policy_data['apprisk'].value_counts().items()],
                ""
            ])

        # 7. Security Recommendations
        report.extend([
            "7. SECURITY RECOMMENDATIONS",
            "-"*80
        ])
        
        # Generate recommendations based on analysis
        recommendations = self._generate_recommendations()
        report.extend([f"  {i+1}. {rec}" for i, rec in enumerate(recommendations)])
        report.append("")
        
        # 8. Potential Security Concerns
        report.extend([
            "8. POTENTIAL SECURITY CONCERNS",
            "-"*80
        ])
        
        # Identify potential security issues
        security_concerns = self._identify_security_concerns()
        report.extend([f"  - {concern}" for concern in security_concerns])
        report.append("")
        
        # Report Footer
        report.extend([
            "="*80,
            "END OF REPORT",
            "="*80
        ])
        
        return "\n".join(report)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        try:
            # Risk-based recommendations
            if 'apprisk' in self.df.columns:
                high_risk = self.df[
                    self.df['apprisk'].fillna('').str.lower().isin(['elevated', 'high'])
                ]
                if not high_risk.empty and 'app' in high_risk.columns:
                    risky_apps = high_risk['app'].unique()
                    if len(risky_apps) > 0:
                        recommendations.append(
                            f"Review and potentially restrict high-risk applications: {', '.join(risky_apps[:3])}"
                        )
            
            # Blocked traffic recommendations
            if 'action' in self.df.columns:
                blocked = self.df[self.df['action'] == 'deny']
                if not blocked.empty:
                    recommendations.append(
                        "Investigate patterns in blocked traffic to identify potential security threats"
                    )
                    
                    if 'service' in blocked.columns:
                        top_blocked_services = blocked['service'].value_counts().head(3)
                        if not top_blocked_services.empty:
                            recommendations.append(
                                f"Review frequently blocked services: {', '.join(top_blocked_services.index)}"
                            )
            
            # Port-based recommendations
            if 'dstport' in self.df.columns:
                common_ports = {'80', '443', '53', '22', '3389'}
                unusual_ports = set(str(p) for p in self.df['dstport'].unique() if str(p) not in common_ports)
                if unusual_ports:
                    recommendations.append(
                        f"Review traffic on unusual ports: {', '.join(sorted(list(unusual_ports))[:5])}"
                    )
            
            # Geographic recommendations
            if 'dstcountry' in self.df.columns:
                foreign_traffic = self.df[self.df['dstcountry'] != self.df['srccountry']]
                if not foreign_traffic.empty:
                    recommendations.append(
                        "Consider implementing geographic-based access controls for international traffic"
                    )
            
            # Wireless recommendations
            if 'signal' in self.df.columns:
                weak_signals = (self.df['signal'] < -70).sum()
                if weak_signals > 0:
                    recommendations.append(
                        "Review wireless coverage due to detected weak signal strengths"
                    )
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {str(e)}")
            recommendations.append(f"Error during analysis: {str(e)}")
        
        # Add general recommendations
        recommendations.extend([
            "Regularly review and update security policies",
            "Implement detailed logging for critical systems",
            "Consider implementing network segmentation",
            "Review and optimize policy configuration regularly"
        ])
        
        return recommendations
    
    def _identify_security_concerns(self) -> List[str]:
        """Identify potential security concerns with enhanced error handling"""
        concerns = []
        
        try:
            # Split analysis by subtype
            for subtype in ['forward', 'local']:
                subtype_df = self.df[self.df['subtype'] == subtype]
                if subtype_df.empty:
                    continue

                # Forward-specific concerns
                if subtype == 'forward':
                    try:
                        # Only check apprisk for forward traffic
                        if 'apprisk' in subtype_df.columns and subtype_df['apprisk'].notna().any():
                            high_risk_apps = subtype_df[subtype_df['apprisk'] == 'elevated']
                            if not high_risk_apps.empty:
                                concerns.append(
                                    f"Detected {len(high_risk_apps)} forwarded connections using high-risk applications"
                                )
                    except Exception as e:
                        self.logger.warning(f"Error checking apprisk in forward traffic: {str(e)}")

                # Common concerns for both types
                try:
                    if 'action' in subtype_df.columns:
                        blocked = subtype_df[subtype_df['action'] == 'deny']
                        if not blocked.empty:
                            concerns.append(
                                f"Detected {len(blocked)} blocked {subtype} connection attempts"
                            )
                except Exception as e:
                    self.logger.warning(f"Error checking blocked traffic for {subtype}: {str(e)}")

                try:
                    if 'sentbyte' in subtype_df.columns:
                        avg_bytes = subtype_df['sentbyte'].mean()
                        high_traffic = subtype_df[subtype_df['sentbyte'] > avg_bytes * 5]
                        if not high_traffic.empty:
                            concerns.append(
                                f"Identified {len(high_traffic)} instances of abnormally high {subtype} traffic volume"
                            )
                except Exception as e:
                    self.logger.warning(f"Error checking traffic volume for {subtype}: {str(e)}")

                # Check suspicious countries if field exists
                try:
                    if 'dstcountry' in subtype_df.columns:
                        suspicious_countries = {'China', 'Russia', 'North Korea'}
                        suspicious_traffic = subtype_df[subtype_df['dstcountry'].isin(suspicious_countries)]
                        if not suspicious_traffic.empty:
                            concerns.append(
                                f"Detected {subtype} traffic to potentially suspicious countries: " +
                                f"{', '.join(suspicious_traffic['dstcountry'].unique())}"
                            )
                except Exception as e:
                    self.logger.warning(f"Error checking suspicious countries for {subtype}: {str(e)}")

        except Exception as e:
            self.logger.error(f"Error identifying security concerns: {str(e)}")
            concerns.append(f"Error during security analysis: {str(e)}")
        
        return concerns

# Usage example
if __name__ == "__main__":
    # Using forticloud.log file
    log_file = Path("forticloud.log")
    analyzer = FortiGateLogAnalyzer(logs=log_file)
    report = analyzer.generate_text_report()
    
    # Save report to file
    output_file = Path("firewall_analysis_report.txt")
    output_file.write_text(report)
    print(f"Report has been saved to: {output_file.absolute()}")