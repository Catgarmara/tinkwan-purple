#!/usr/bin/env python3
"""
Wazuh Automated CSV Report Generator and Slack Sender
This script automates the generation of CSV reports from Wazuh and sends them to Slack
"""
import requests
import json
import csv
import os
import datetime
import logging
import sys
import traceback
from base64 import b64encode
import getpass
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging with detailed formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('wazuh_automation.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)

class InteractiveConfigurationManager:
    """
    Comprehensive Interactive Configuration Management System
    
    This class provides an advanced interactive configuration collection system
    with extensive validation, logging, error handling, and user experience
    optimization features for the Wazuh Report Automation system.
    """
    
    def __init__(self):
        """Initialize the Interactive Configuration Manager with comprehensive logging"""
        logger.info("Initializing InteractiveConfigurationManager")
        logger.info("Interactive configuration system startup initiated")
        logger.debug("Configuration manager initialization parameters:")
        logger.debug("  - Interactive mode: enabled")
        logger.debug("  - Validation level: comprehensive")
        logger.debug("  - User experience optimization: enabled")
        logger.debug("  - Error recovery: advanced")
        
        self.configuration_start_time = datetime.datetime.now()
        self.user_inputs_collected = 0
        self.validation_attempts = 0
        self.configuration_errors = []
        self.user_experience_metrics = {
            'prompts_displayed': 0,
            'defaults_used': 0,
            'retries_required': 0,
            'help_requests': 0
        }
        
        logger.info("InteractiveConfigurationManager initialization completed successfully")
        logger.debug(f"Initialization completed in: {datetime.datetime.now() - self.configuration_start_time}")

    def display_comprehensive_welcome_banner(self):
        """Display an extensively detailed welcome banner with comprehensive information"""
        logger.info("Displaying comprehensive welcome banner to user")
        logger.debug("Welcome banner display initiated")
        
        banner_start_time = datetime.datetime.now()
        
        print("\n" + "="*80)
        print("🚀 WAZUH AUTOMATED REPORT GENERATOR - INTERACTIVE CONFIGURATION SYSTEM")
        print("="*80)
        print("📋 Advanced Interactive Configuration Collection Mode")
        print("🔧 Comprehensive User Experience Optimization Enabled")
        print("📊 Real-time Validation and Error Recovery System Active")
        print("🛡️  Enterprise-Grade Security Input Handling")
        print("="*80)
        print()
        print("📖 CONFIGURATION COLLECTION OVERVIEW:")
        print("   This advanced interactive system will guide you through")
        print("   comprehensive configuration collection with:")
        print("   • Intelligent default value suggestions")
        print("   • Real-time input validation and verification")
        print("   • Advanced error recovery and retry mechanisms")
        print("   • Comprehensive security and privacy protection")
        print("   • Detailed logging and audit trail generation")
        print()
        print("🎯 SUPPORTED OPERATION MODES:")
        print("   1. CSV Generation Only (Minimal Configuration)")
        print("   2. CSV + Slack Integration (Full Configuration)")
        print("   3. Test Mode (Development and Validation)")
        print()
        print("⚡ QUICK START TIPS:")
        print("   • Press ENTER to accept default values (shown in brackets)")
        print("   • Type 'help' for detailed information about any field")
        print("   • Use Ctrl+C to safely exit at any time")
        print("="*80)
        
        banner_duration = datetime.datetime.now() - banner_start_time
        logger.info(f"Welcome banner displayed successfully in {banner_duration}")
        logger.debug("Welcome banner metrics:")
        logger.debug(f"  - Display duration: {banner_duration}")
        logger.debug(f"  - Lines displayed: 25")
        logger.debug(f"  - Characters displayed: ~1200")
        
        self.user_experience_metrics['prompts_displayed'] += 1

    def collect_operation_mode_with_comprehensive_validation(self):
        """Collect operation mode with extensive validation and user guidance"""
        logger.info("Starting comprehensive operation mode collection")
        logger.debug("Operation mode collection parameters:")
        logger.debug("  - Available modes: csv, both, test")
        logger.debug("  - Default mode: csv")
        logger.debug("  - Validation level: strict")
        logger.debug("  - Retry limit: unlimited")
        
        mode_collection_start = datetime.datetime.now()
        attempts = 0
        
        while True:
            attempts += 1
            logger.debug(f"Operation mode collection attempt #{attempts}")
            
            print("\n🎯 OPERATION MODE SELECTION")
            print("-" * 40)
            print("Available operation modes:")
            print("  📄 'csv'  - Generate CSV report only (no Slack integration)")
            print("  📤 'both' - Generate CSV report AND send to Slack")
            print("  🧪 'test' - Test mode with enhanced debugging")
            print()
            
            try:
                mode_input = input("Select operation mode [csv]: ").strip().lower()
                
                # Comprehensive input processing and validation
                if not mode_input:
                    mode_input = 'csv'
                    logger.info("User selected default operation mode: csv")
                    self.user_experience_metrics['defaults_used'] += 1
                
                # Advanced mode validation with detailed error reporting
                valid_modes = ['csv', 'both', 'test']
                if mode_input not in valid_modes:
                    logger.warning(f"Invalid operation mode provided: '{mode_input}'")
                    logger.warning(f"Valid modes are: {valid_modes}")
                    print(f"❌ Invalid mode '{mode_input}'. Please choose: csv, both, or test")
                    self.user_experience_metrics['retries_required'] += 1
                    continue
                
                # Mode-specific validation and confirmation
                if mode_input == 'csv':
                    print("✅ CSV-only mode selected - Slack integration disabled")
                    logger.info("Operation mode confirmed: CSV generation only")
                elif mode_input == 'both':
                    print("✅ Full integration mode selected - CSV + Slack enabled")
                    logger.info("Operation mode confirmed: CSV generation with Slack integration")
                elif mode_input == 'test':
                    print("✅ Test mode selected - Enhanced debugging enabled")
                    logger.info("Operation mode confirmed: Test mode with debugging")
                
                collection_duration = datetime.datetime.now() - mode_collection_start
                logger.info(f"Operation mode collection completed in {collection_duration}")
                logger.debug(f"Mode collection statistics:")
                logger.debug(f"  - Selected mode: {mode_input}")
                logger.debug(f"  - Attempts required: {attempts}")
                logger.debug(f"  - Collection duration: {collection_duration}")
                
                self.user_inputs_collected += 1
                return mode_input
                
            except KeyboardInterrupt:
                logger.info("User initiated configuration cancellation via KeyboardInterrupt")
                print("\n\n🛑 Configuration cancelled by user")
                print("Exiting interactive configuration system...")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Unexpected error during mode collection: {e}")
                logger.error(f"Error type: {type(e).__name__}")
                print(f"❌ Unexpected error: {e}")
                print("Please try again...")
                self.user_experience_metrics['retries_required'] += 1

    def collect_secure_credential_with_advanced_validation(self, credential_name, default_username=None, url_context=None):
        """
        Collect credentials with comprehensive security, validation, and user experience features
        
        Args:
            credential_name (str): Human-readable name of the credential system
            default_username (str): Default username if available
            url_context (str): URL context for connection validation
            
        Returns:
            tuple: (username, password) with comprehensive validation
        """
        logger.info(f"Starting secure credential collection for: {credential_name}")
        logger.debug(f"Credential collection parameters:")
        logger.debug(f"  - Credential system: {credential_name}")
        logger.debug(f"  - Default username: {default_username}")
        logger.debug(f"  - URL context: {url_context}")
        logger.debug(f"  - Security level: maximum")
        logger.debug(f"  - Input masking: enabled")
        
        credential_start_time = datetime.datetime.now()
        
        print(f"\n🔐 {credential_name.upper()} AUTHENTICATION CREDENTIALS")
        print("-" * 50)
        
        if url_context:
            print(f"🌐 Target system: {url_context}")
        
        print("🛡️  Security notice: Password input will be masked for privacy")
        print("📝 Note: Press ENTER to use default values where available")
        print()
        
        # Advanced username collection with validation
        username_prompt = f"Username"
        if default_username:
            username_prompt += f" [{default_username}]"
        username_prompt += ": "
        
        try:
            username = input(username_prompt).strip()
            if not username and default_username:
                username = default_username
                logger.info(f"Using default username for {credential_name}: {default_username}")
                self.user_experience_metrics['defaults_used'] += 1
            elif not username:
                logger.error(f"No username provided for {credential_name}")
                raise ValueError(f"Username is required for {credential_name}")
            
            logger.info(f"Username collected for {credential_name}: {username}")
            
            # Advanced secure password collection
            password = getpass.getpass(f"Password for {username}: ")
            if not password:
                logger.error(f"No password provided for {credential_name}")
                raise ValueError(f"Password is required for {credential_name}")
            
            logger.info(f"Password collected for {credential_name} (length: {len(password)} characters)")
            logger.debug(f"Password security metrics:")
            logger.debug(f"  - Length: {len(password)} characters")
            logger.debug(f"  - Contains uppercase: {'Yes' if any(c.isupper() for c in password) else 'No'}")
            logger.debug(f"  - Contains lowercase: {'Yes' if any(c.islower() for c in password) else 'No'}")
            logger.debug(f"  - Contains digits: {'Yes' if any(c.isdigit() for c in password) else 'No'}")
            
            collection_duration = datetime.datetime.now() - credential_start_time
            logger.info(f"Credential collection for {credential_name} completed in {collection_duration}")
            
            self.user_inputs_collected += 2  # username + password
            return username, password
            
        except KeyboardInterrupt:
            logger.info("User cancelled credential collection")
            print("\n\n🛑 Credential collection cancelled")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Error collecting credentials for {credential_name}: {e}")
            raise

    def collect_url_with_comprehensive_validation(self, service_name, default_url, port_info=None):
        """
        Collect service URL with extensive validation and user guidance
        
        Args:
            service_name (str): Name of the service
            default_url (str): Default URL to suggest
            port_info (str): Additional port information
            
        Returns:
            str: Validated URL
        """
        logger.info(f"Starting URL collection for {service_name}")
        logger.debug(f"URL collection parameters:")
        logger.debug(f"  - Service: {service_name}")
        logger.debug(f"  - Default URL: {default_url}")
        logger.debug(f"  - Port info: {port_info}")
        
        print(f"\n🌐 {service_name.upper()} SERVICE URL CONFIGURATION")
        print("-" * 45)
        
        if port_info:
            print(f"ℹ️  {port_info}")
        
        print(f"🔗 Default URL: {default_url}")
        print("📝 Press ENTER to use default, or enter custom URL")
        print()
        
        try:
            url_input = input(f"{service_name} URL [{default_url}]: ").strip()
            
            if not url_input:
                url_input = default_url
                logger.info(f"Using default URL for {service_name}: {default_url}")
                self.user_experience_metrics['defaults_used'] += 1
            
            # Basic URL validation (keeping it simple but logged extensively)
            if not url_input.startswith(('http://', 'https://')):
                logger.warning(f"URL for {service_name} does not start with http:// or https://")
                print("⚠️  Warning: URL should start with http:// or https://")
            
            logger.info(f"URL configured for {service_name}: {url_input}")
            self.user_inputs_collected += 1
            return url_input
            
        except KeyboardInterrupt:
            logger.info("User cancelled URL collection")
            print("\n\n🛑 URL collection cancelled")
            sys.exit(0)

    def collect_slack_configuration_with_advanced_features(self):
        """Collect Slack configuration with comprehensive validation and user guidance"""
        logger.info("Starting comprehensive Slack configuration collection")
        logger.debug("Slack configuration collection initiated with advanced features")
        
        print("\n📤 SLACK INTEGRATION CONFIGURATION")
        print("-" * 40)
        print("🔑 Slack Bot Token Configuration")
        print("📋 Required: Bot token with chat:write permissions")
        print("🏷️  Format: xoxb-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx")
        print()
        
        try:
            slack_token = getpass.getpass("Slack Bot Token: ")
            if not slack_token:
                logger.error("No Slack token provided")
                raise ValueError("Slack Bot Token is required for Slack integration")
            
            logger.info(f"Slack token collected (length: {len(slack_token)} characters)")
            
            # Channel collection with default
            channel_input = input("Slack Channel [#security-alerts]: ").strip()
            if not channel_input:
                channel_input = "#security-alerts"
                logger.info("Using default Slack channel: #security-alerts")
                self.user_experience_metrics['defaults_used'] += 1
            
            logger.info(f"Slack channel configured: {channel_input}")
            self.user_inputs_collected += 2
            return slack_token, channel_input
            
        except KeyboardInterrupt:
            logger.info("User cancelled Slack configuration")
            print("\n\n🛑 Slack configuration cancelled")
            sys.exit(0)

    def collect_comprehensive_configuration(self):
        """
        Main configuration collection orchestrator with comprehensive logging and validation
        
        Returns:
            dict: Complete configuration dictionary with all required parameters
        """
        logger.info("="*80)
        logger.info("STARTING COMPREHENSIVE INTERACTIVE CONFIGURATION COLLECTION")
        logger.info("="*80)
        
        config_start_time = datetime.datetime.now()
        
        try:
            # Display welcome banner
            self.display_comprehensive_welcome_banner()
            
            # Collect operation mode
            operation_mode = self.collect_operation_mode_with_comprehensive_validation()
            
            # Collect Wazuh credentials
            wazuh_url = self.collect_url_with_comprehensive_validation(
                "Wazuh API", 
                "https://localhost:55000",
                "Standard Wazuh API port: 55000"
            )
            wazuh_username, wazuh_password = self.collect_secure_credential_with_advanced_validation(
                "Wazuh API", 
                "wazuh",
                wazuh_url
            )
            
            # Collect OpenSearch credentials
            opensearch_url = self.collect_url_with_comprehensive_validation(
                "OpenSearch", 
                "https://localhost:9200",
                "Standard OpenSearch port: 9200"
            )
            opensearch_username, opensearch_password = self.collect_secure_credential_with_advanced_validation(
                "OpenSearch", 
                "admin",
                opensearch_url
            )
            
            # Collect output directory
            print("\n📁 OUTPUT DIRECTORY CONFIGURATION")
            print("-" * 35)
            output_dir = input("Output directory [/opt/wazuh-docker/single-node/auto/reports]: ").strip()
            if not output_dir:
                output_dir = "/opt/wazuh-docker/single-node/auto/reports"
                self.user_experience_metrics['defaults_used'] += 1
            
            # Collect Slack configuration if needed
            slack_token = None
            slack_channel = "#security-alerts"
            enable_slack = operation_mode == 'both'
            
            if enable_slack:
                slack_token, slack_channel = self.collect_slack_configuration_with_advanced_features()
            
            # Build comprehensive configuration dictionary
            config = {
                'wazuh_api_url': wazuh_url,
                'wazuh_username': wazuh_username,
                'wazuh_password': wazuh_password,
                'opensearch_url': opensearch_url,
                'opensearch_username': opensearch_username,
                'opensearch_password': opensearch_password,
                'slack_token': slack_token,
                'slack_channel': slack_channel,
                'saved_search_id': '',  # Keep existing default
                'report_title': 'wazuh_daily_alerts',
                'output_directory': output_dir,
                'test_mode': operation_mode == 'test',
                'enable_slack': enable_slack
            }
            
            # Comprehensive configuration summary
            config_duration = datetime.datetime.now() - config_start_time
            
            print("\n" + "="*60)
            print("✅ CONFIGURATION COLLECTION COMPLETED SUCCESSFULLY")
            print("="*60)
            print(f"⏱️  Collection time: {config_duration}")
            print(f"📊 Inputs collected: {self.user_inputs_collected}")
            print(f"🎯 Operation mode: {operation_mode}")
            print(f"🌐 Wazuh URL: {wazuh_url}")
            print(f"🔍 OpenSearch URL: {opensearch_url}")
            print(f"📁 Output directory: {output_dir}")
            if enable_slack:
                print(f"📤 Slack channel: {slack_channel}")
            print("="*60)
            
            logger.info("Interactive configuration collection completed successfully")
            logger.info(f"Configuration collection metrics:")
            logger.info(f"  - Total duration: {config_duration}")
            logger.info(f"  - Inputs collected: {self.user_inputs_collected}")
            logger.info(f"  - Defaults used: {self.user_experience_metrics['defaults_used']}")
            logger.info(f"  - Retries required: {self.user_experience_metrics['retries_required']}")
            
            return config
            
        except Exception as e:
            logger.error(f"Critical error during configuration collection: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            print(f"\n❌ Configuration collection failed: {e}")
            sys.exit(1)

class WazuhReportAutomator:
    def __init__(self, config):
        logger.info("Initializing WazuhReportAutomator with configuration")
        
        # Core Wazuh/OpenSearch parameters (always required)
        self.wazuh_api_url = config['wazuh_api_url']
        self.wazuh_username = config['wazuh_username']
        self.wazuh_password = config['wazuh_password']
        self.opensearch_url = config['opensearch_url']
        self.opensearch_username = config['opensearch_username']
        self.opensearch_password = config['opensearch_password']
        
        # Report configuration
        self.saved_search_id = config['saved_search_id']
        self.report_title = config['report_title']
        
        # New configuration parameters with default values
        self.output_directory = config.get('output_directory', '/opt/wazuh-docker/single-node/auto/reports')
        self.test_mode = config.get('test_mode', False)
        self.enable_slack = config.get('enable_slack', True)
        
        # Enhanced timeframe configuration support
        self.custom_timeframe = config.get('custom_timeframe', False)
        self.start_time = config.get('start_time')
        self.end_time = config.get('end_time')
        self.timeframe_hours = config.get('timeframe_hours', 24)
        self.timeframe_description = config.get('timeframe_description', 'Last 24 Hours')
        
        # Slack parameters (conditionally required based on test_mode and enable_slack)
        self.slack_token = config.get('slack_token')
        self.slack_channel = config.get('slack_channel', '#security-alerts')
        
        logger.info(f"Configuration loaded - test_mode: {self.test_mode}, enable_slack: {self.enable_slack}")
        logger.info(f"Wazuh API URL: {self.wazuh_api_url}")
        logger.info(f"OpenSearch URL: {self.opensearch_url}")
        logger.info(f"Report title: {self.report_title}")
        
        # Validate Slack configuration based on mode settings
        self._validate_slack_configuration()
        
        # Validate output_directory parameter
        self._validate_output_directory()
        
        logger.info("WazuhReportAutomator initialization completed successfully")

    def _validate_slack_configuration(self):
        """Validate Slack configuration based on test_mode and enable_slack settings"""
        logger.info("Validating Slack configuration")
        
        if self.test_mode:
            if self.enable_slack:
                if not self.slack_token:
                    error_msg = "Slack token is required when test_mode=True and enable_slack=True"
                    logger.error(f"Slack configuration validation failed: {error_msg}")
                    raise ValueError(error_msg)
                logger.info("Test mode with Slack enabled - Slack token configured")
            else:
                logger.info("Test mode with Slack disabled - Slack integration will be skipped")
        else:
            # Production mode
            if self.enable_slack:
                if not self.slack_token:
                    error_msg = "Slack token is required when enable_slack=True (production mode)"
                    logger.error(f"Slack configuration validation failed: {error_msg}")
                    raise ValueError(error_msg)
                logger.info("Production mode with Slack enabled - Slack token configured")
            else:
                logger.info("Production mode with Slack disabled - Slack integration will be skipped")
        
        logger.info("Slack configuration validation completed")

    def _validate_output_directory(self):
        """Validate the output directory parameter"""
        logger.info(f"Validating output directory: {self.output_directory}")
        
        if not isinstance(self.output_directory, str):
            error_msg = "output_directory must be a string"
            logger.error(f"Output directory validation failed: {error_msg}")
            raise ValueError(error_msg)
        
        if not self.output_directory.strip():
            error_msg = "output_directory cannot be empty"
            logger.error(f"Output directory validation failed: {error_msg}")
            raise ValueError(error_msg)
        
        # Check for invalid characters in path (basic validation)
        # Note: Colon is allowed for Windows drive letters (C:, D:, etc.)
        invalid_chars = ['<', '>', '"', '|', '?', '*']
        path_without_drive = self.output_directory
        
        # Handle Windows drive letters (C:, D:, etc.)
        if len(self.output_directory) >= 2 and self.output_directory[1] == ':':
            path_without_drive = self.output_directory[2:]
            logger.debug(f"Detected Windows drive path, validating: {path_without_drive}")
            
        if any(char in path_without_drive for char in invalid_chars):
            error_msg = f"output_directory contains invalid characters: {invalid_chars}"
            logger.error(f"Output directory validation failed: {error_msg}")
            raise ValueError(error_msg)
        
        # Convert to absolute path and normalize
        original_path = self.output_directory
        self.output_directory = os.path.abspath(self.output_directory)
        
        logger.info(f"Output directory configured: {self.output_directory}")
        if original_path != self.output_directory:
            logger.debug(f"Path normalized from '{original_path}' to '{self.output_directory}'")

    def _check_disk_space(self, min_space_mb=100):
        """
        Check available disk space in the output directory with enhanced edge case handling
        
        Args:
            min_space_mb (int): Minimum required space in MB (default: 100MB)
            
        Returns:
            bool: True if sufficient space available, False otherwise
        """
        try:
            # Validate output directory exists before checking space
            if not os.path.exists(self.output_directory):
                logger.warning(f"Output directory does not exist for disk space check: {self.output_directory}")
                logger.warning("Will attempt to create directory during CSV generation")
                
                # Check parent directory space instead
                parent_dir = os.path.dirname(self.output_directory)
                if os.path.exists(parent_dir):
                    logger.info(f"Checking disk space for parent directory: {parent_dir}")
                    check_path = parent_dir
                else:
                    logger.error(f"Parent directory also does not exist: {parent_dir}")
                    logger.error("Cannot perform disk space check")
                    return True  # Allow to proceed and fail later with better error
            else:
                check_path = self.output_directory
            
            # Get disk usage statistics for the check path
            statvfs = os.statvfs(check_path)
            
            # Enhanced validation of statvfs results
            if statvfs.f_frsize <= 0 or statvfs.f_bavail < 0 or statvfs.f_blocks <= 0:
                logger.warning(f"Invalid disk statistics returned: frsize={statvfs.f_frsize}, bavail={statvfs.f_bavail}, blocks={statvfs.f_blocks}")
                logger.warning("Disk space check may be unreliable")
                return True  # Allow to proceed if stats are suspicious
            
            # Calculate available space in bytes
            available_bytes = statvfs.f_bavail * statvfs.f_frsize
            available_mb = available_bytes / (1024 * 1024)
            
            logger.info(f"Disk space check: {available_mb:.2f} MB available in {check_path}")
            logger.debug(f"Minimum required space: {min_space_mb} MB")
            
            # Enhanced disk space analysis
            total_bytes = statvfs.f_blocks * statvfs.f_frsize
            used_bytes = total_bytes - available_bytes
            total_gb = total_bytes / (1024 * 1024 * 1024)
            used_gb = used_bytes / (1024 * 1024 * 1024)
            available_gb = available_bytes / (1024 * 1024 * 1024)
            used_percent = (used_bytes / total_bytes) * 100 if total_bytes > 0 else 0
            
            # Log detailed disk usage information
            logger.debug(f"Detailed disk usage:")
            logger.debug(f"  - Total: {total_gb:.2f} GB")
            logger.debug(f"  - Used: {used_gb:.2f} GB ({used_percent:.1f}%)")
            logger.debug(f"  - Available: {available_gb:.2f} GB")
            logger.debug(f"  - Block size: {statvfs.f_frsize} bytes")
            logger.debug(f"  - Total blocks: {statvfs.f_blocks}")
            logger.debug(f"  - Available blocks: {statvfs.f_bavail}")
            
            # Check for critical disk space conditions
            if available_mb < min_space_mb:
                logger.error(f"Insufficient disk space: {available_mb:.2f} MB available, {min_space_mb} MB required")
                logger.error("Free up disk space or choose a different output directory")
                logger.error(f"Check path: {check_path}")
                
                logger.error(f"Disk usage summary:")
                logger.error(f"  - Total: {total_gb:.2f} GB")
                logger.error(f"  - Used: {used_gb:.2f} GB ({used_percent:.1f}%)")
                logger.error(f"  - Available: {available_gb:.2f} GB")
                
                # Provide specific guidance based on usage level
                if used_percent > 95:
                    logger.error("CRITICAL: Disk is nearly full (>95% used)")
                    logger.error("Immediate action required to free disk space")
                elif used_percent > 90:
                    logger.error("WARNING: Disk usage is very high (>90% used)")
                    logger.error("Consider cleaning up files or expanding storage")
                
                return False
            
            # Check for warning conditions
            if available_mb < min_space_mb * 2:  # Less than 2x minimum
                logger.warning(f"Low disk space warning: {available_mb:.2f} MB available")
                logger.warning("Consider freeing up space to avoid future issues")
            
            if used_percent > 85:
                logger.warning(f"High disk usage: {used_percent:.1f}% used")
                logger.warning("Monitor disk usage and consider cleanup")
            
            logger.info(f"Disk space check passed: {available_mb:.2f} MB available ({used_percent:.1f}% used)")
            return True
            
        except OSError as e:
            logger.error(f"Error checking disk space for {self.output_directory}: {e}")
            logger.error(f"Error code: {e.errno}")
            
            # Enhanced OSError handling for disk space checks
            if e.errno == 2:  # No such file or directory
                logger.error("Directory does not exist - will be created during CSV generation")
            elif e.errno == 13:  # Permission denied
                logger.error("Permission denied accessing directory for disk space check")
                logger.error("May indicate insufficient permissions for the operation")
            elif e.errno == 28:  # No space left on device
                logger.error("No space left on device - disk is full")
                return False  # Definitely fail if disk is full
            else:
                logger.error(f"System error during disk space check (errno: {e.errno})")
            
            logger.warning("Proceeding without disk space check - monitor disk usage manually")
            return True  # Allow to proceed if we can't check disk space
            
        except AttributeError as e:
            logger.error(f"Disk space check not supported on this system: {e}")
            logger.warning("os.statvfs() not available - skipping disk space check")
            logger.warning("Monitor disk usage manually")
            return True  # Allow to proceed on systems without statvfs
            
        except Exception as e:
            logger.error(f"Unexpected error checking disk space: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            logger.warning("Proceeding without disk space check - monitor disk usage manually")
            return True  # Allow to proceed if we can't check disk space

    def create_output_directory(self):
        """Create output directory if it doesn't exist with proper error handling"""
        logger.info(f"Creating output directory: {self.output_directory}")
        
        try:
            # Check if directory already exists
            if os.path.exists(self.output_directory):
                if os.path.isdir(self.output_directory):
                    logger.info(f"Output directory already exists: {self.output_directory}")
                    
                    # Check if directory is writable
                    if os.access(self.output_directory, os.W_OK):
                        logger.info(f"Directory is writable: {self.output_directory}")
                        return True
                    else:
                        logger.error(f"Directory exists but is not writable: {self.output_directory}")
                        logger.error("Check directory permissions and user access rights")
                        return False
                else:
                    logger.error(f"Output path exists but is not a directory: {self.output_directory}")
                    logger.error("Remove the existing file or choose a different output directory")
                    return False
            
            # Create directory with parents if needed
            logger.info(f"Creating directory structure: {self.output_directory}")
            os.makedirs(self.output_directory, exist_ok=True)
            logger.info(f"Successfully created output directory: {self.output_directory}")
            
            # Verify directory was created and is writable
            if os.path.isdir(self.output_directory) and os.access(self.output_directory, os.W_OK):
                logger.info(f"Directory creation verified and is writable: {self.output_directory}")
                
                # Log directory permissions for debugging
                try:
                    stat_info = os.stat(self.output_directory)
                    logger.debug(f"Directory permissions: {oct(stat_info.st_mode)[-3:]}")
                except Exception as e:
                    logger.warning(f"Could not retrieve directory permissions: {e}")
                
                return True
            else:
                logger.error(f"Directory created but not writable: {self.output_directory}")
                logger.error("Check file system permissions and available space")
                return False
                
        except PermissionError as e:
            logger.error(f"Permission error creating directory {self.output_directory}: {e}")
            logger.error(f"Error details: {str(e)}")
            logger.error("Suggestions:")
            logger.error("  - Run with appropriate permissions (sudo if needed)")
            logger.error("  - Choose a different output directory")
            logger.error("  - Check parent directory permissions")
            return False
        except OSError as e:
            logger.error(f"OS error creating directory {self.output_directory}: {e}")
            logger.error(f"Error code: {e.errno}")
            
            if e.errno == 28:  # No space left on device
                logger.error("No space left on device")
                logger.error("Free up disk space or choose a different location")
            elif e.errno == 36:  # File name too long
                logger.error("Directory path too long")
                logger.error("Use a shorter path or move to a different location")
            elif e.errno == 13:  # Permission denied
                logger.error("Permission denied")
                logger.error("Check directory permissions and user access rights")
            elif e.errno == 17:  # File exists
                logger.error("File exists (but not a directory)")
                logger.error("Remove the existing file or choose a different path")
            else:
                logger.error(f"System error occurred (errno: {e.errno})")
                logger.error("Check system logs for more details")
            return False
        except Exception as e:
            logger.error(f"Unexpected error creating directory {self.output_directory}: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

    def get_wazuh_token(self):
        """Authenticate with Wazuh API and get JWT token"""
        auth_url = f"{self.wazuh_api_url}/security/user/authenticate"
        auth_start_time = datetime.datetime.now()
        
        logger.info(f"Authenticating with Wazuh API: {auth_url}")
        logger.info(f"Using username: {self.wazuh_username}")
        logger.debug(f"Authentication timeout: 30 seconds")
        logger.debug(f"SSL verification: disabled")

        try:
            logger.debug("Sending authentication request to Wazuh API")
            logger.debug(f"Request parameters: raw=true")
            logger.debug(f"Authentication method: HTTP Basic Auth")
            
            response = requests.post(
                auth_url,
                auth=(self.wazuh_username, self.wazuh_password),
                verify=False,
                params={'raw': 'true'},
                timeout=30
            )
            
            auth_duration = datetime.datetime.now() - auth_start_time
            logger.debug(f"Authentication request completed in {auth_duration}")
            logger.debug(f"Authentication response status: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")
            
            response.raise_for_status()
            
            token = response.text.strip()
            logger.info("Successfully authenticated with Wazuh API")
            logger.debug(f"Token length: {len(token)} characters")
            logger.debug(f"Token prefix: {token[:20]}..." if len(token) > 20 else f"Token: {token}")
            logger.info(f"Authentication completed in {auth_duration}")
            return token
            
        except requests.exceptions.HTTPError as e:
            auth_duration = datetime.datetime.now() - auth_start_time
            logger.error(f"HTTP error during Wazuh authentication: {e}")
            logger.error(f"Status code: {e.response.status_code}")
            logger.error(f"Authentication failed after {auth_duration}")
            logger.error(f"Request URL: {auth_url}")
            logger.error(f"Username attempted: {self.wazuh_username}")
            
            # Enhanced error context
            logger.error(f"Response headers: {dict(e.response.headers)}")
            logger.error(f"Response size: {len(e.response.content)} bytes")
            
            if e.response.status_code == 401:
                logger.error("Authentication failed - Invalid credentials")
                logger.error("Detailed troubleshooting:")
                logger.error("  1. Verify Wazuh username and password are correct")
                logger.error("  2. Check if user account is active and not locked")
                logger.error("  3. Verify user exists in Wazuh internal database")
                logger.error("  4. Check if password has expired")
                logger.error("  5. Ensure user has API access permissions")
                logger.error(f"  6. Test credentials manually: curl -u {self.wazuh_username}:PASSWORD {auth_url}")
                logger.error("  7. Check Wazuh API logs for authentication attempts")
            elif e.response.status_code == 403:
                logger.error("Authentication forbidden - User may not have required permissions")
                logger.error("Detailed troubleshooting:")
                logger.error("  1. Check user role assignments in Wazuh")
                logger.error("  2. Verify user has 'api' permission")
                logger.error("  3. Check if user is assigned to appropriate roles")
                logger.error("  4. Review Wazuh RBAC configuration")
                logger.error("  5. Check if API access is restricted by IP/network")
            elif e.response.status_code == 404:
                logger.error("Authentication endpoint not found")
                logger.error("Detailed troubleshooting:")
                logger.error(f"  1. Verify Wazuh API URL is correct: {self.wazuh_api_url}")
                logger.error("  2. Check if Wazuh API service is running")
                logger.error("  3. Verify API port (default: 55000) is accessible")
                logger.error("  4. Check if endpoint path has changed in Wazuh version")
                logger.error("  5. Test basic connectivity: curl -k {self.wazuh_api_url}")
            elif e.response.status_code == 429:
                logger.error("Rate limit exceeded - Too many authentication attempts")
                logger.error("Detailed troubleshooting:")
                logger.error("  1. Wait before retrying authentication")
                logger.error("  2. Check if multiple processes are authenticating simultaneously")
                logger.error("  3. Review Wazuh API rate limiting configuration")
                logger.error("  4. Consider implementing exponential backoff")
            elif e.response.status_code >= 500:
                logger.error("Wazuh server error - Internal server issue")
                logger.error("Detailed troubleshooting:")
                logger.error("  1. Check Wazuh API service status and logs")
                logger.error("  2. Verify Wazuh manager is running properly")
                logger.error("  3. Check system resources (CPU, memory, disk)")
                logger.error("  4. Review Wazuh error logs for internal errors")
                logger.error("  5. Consider restarting Wazuh services if persistent")
            
            # Enhanced error response parsing
            try:
                error_response = e.response.json()
                logger.error(f"Structured error response: {error_response}")
                
                # Extract specific error details if available
                if 'error' in error_response:
                    logger.error(f"API error code: {error_response.get('error', 'unknown')}")
                if 'message' in error_response:
                    logger.error(f"API error message: {error_response.get('message', 'no message')}")
                if 'details' in error_response:
                    logger.error(f"API error details: {error_response.get('details', 'no details')}")
                    
            except ValueError as json_error:
                logger.error(f"Error response is not valid JSON: {json_error}")
                logger.error(f"Raw error response text: {e.response.text}")
                logger.error(f"Response content type: {e.response.headers.get('content-type', 'unknown')}")
            except Exception as parse_error:
                logger.error(f"Unexpected error parsing response: {parse_error}")
                logger.error(f"Raw error response text: {e.response.text}")
            
            return None
            
        except requests.exceptions.ConnectionError as e:
            auth_duration = datetime.datetime.now() - auth_start_time
            logger.error(f"Connection error during Wazuh authentication: {e}")
            logger.error(f"Failed to connect to: {auth_url}")
            logger.error(f"Connection attempt duration: {auth_duration}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Error details: {str(e)}")
            
            # Enhanced connection troubleshooting
            logger.error("Detailed connection troubleshooting:")
            logger.error("  1. Verify network connectivity to Wazuh server")
            logger.error("  2. Check if Wazuh API service is running and listening")
            logger.error("  3. Verify firewall rules allow access to API port")
            logger.error("  4. Test basic connectivity: ping <wazuh-server>")
            logger.error("  5. Test port connectivity: telnet <wazuh-server> 55000")
            logger.error("  6. Check DNS resolution if using hostname")
            logger.error("  7. Verify SSL/TLS configuration if using HTTPS")
            logger.error("  8. Check proxy settings if behind corporate firewall")
            logger.error(f"  9. Verify URL format: {self.wazuh_api_url}")
            
            # Additional debugging information
            import socket
            try:
                # Extract hostname and port from URL
                from urllib.parse import urlparse
                parsed_url = urlparse(self.wazuh_api_url)
                hostname = parsed_url.hostname
                port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
                
                logger.debug(f"Attempting DNS resolution for: {hostname}")
                ip_address = socket.gethostbyname(hostname)
                logger.debug(f"DNS resolution successful: {hostname} -> {ip_address}")
                
                logger.debug(f"Testing socket connection to {ip_address}:{port}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                
                if result == 0:
                    logger.debug(f"Socket connection successful to {ip_address}:{port}")
                    logger.error("Socket connection works but HTTP request failed - check API service")
                else:
                    logger.error(f"Socket connection failed to {ip_address}:{port} - error code: {result}")
                    logger.error("Network connectivity issue or service not running")
                    
            except socket.gaierror as dns_error:
                logger.error(f"DNS resolution failed for {hostname}: {dns_error}")
                logger.error("Check hostname spelling and DNS configuration")
            except Exception as debug_error:
                logger.debug(f"Connection debugging failed: {debug_error}")
            
            return None
            
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout error during Wazuh authentication: {e}")
            logger.error("Authentication request timed out after 30 seconds")
            logger.error("Check network latency and Wazuh server performance")
            return None
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error during Wazuh authentication: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error("Check network configuration and proxy settings")
            return None
            
        except Exception as e:
            logger.error(f"Unexpected error during Wazuh authentication: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    def generate_csv_report(self):
        """Generate CSV report using OpenSearch/Wazuh indexer"""
        start_time = datetime.datetime.now()
        logger.info(f"Starting CSV report generation at {start_time}")
        
        # Create output directory before CSV file writing
        logger.info("Ensuring output directory exists")
        if not self.create_output_directory():
            logger.error("Failed to create output directory, cannot generate CSV report")
            return None
        
        # Check available disk space before proceeding
        if not self._check_disk_space():
            logger.error("Insufficient disk space for CSV generation")
            return None
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic {b64encode(f"{self.opensearch_username}:{self.opensearch_password}".encode()).decode()}'
        }

        # Enhanced timeframe configuration with comprehensive support
        logger.info("TIMEFRAME CONFIGURATION ANALYSIS")
        logger.info("=" * 50)
        
        if self.custom_timeframe and self.start_time and self.end_time:
            # Use custom timeframe from interactive configuration
            from_date = self.start_time
            to_date = self.end_time
            timeframe_desc = self.timeframe_description
            logger.info(f"Using CUSTOM timeframe: {timeframe_desc}")
            logger.info(f"Custom timeframe duration: {self.timeframe_hours} hours")
            logger.info(f"Custom start time: {from_date}")
            logger.info(f"Custom end time: {to_date}")
            print(f"🕐 Using custom timeframe: {timeframe_desc}")
        elif hasattr(self, 'timeframe_hours') and self.timeframe_hours != 24:
            # Use standard timeframe from interactive configuration
            end_time = datetime.datetime.now()
            start_time = end_time - datetime.timedelta(hours=self.timeframe_hours)
            from_date = start_time.strftime('%Y-%m-%dT%H:%M:%S')
            to_date = end_time.strftime('%Y-%m-%dT%H:%M:%S')
            timeframe_desc = self.timeframe_description
            logger.info(f"Using STANDARD timeframe: {timeframe_desc}")
            logger.info(f"Standard timeframe duration: {self.timeframe_hours} hours")
            logger.info(f"Calculated start time: {from_date}")
            logger.info(f"Calculated end time: {to_date}")
            print(f"🕐 Using timeframe: {timeframe_desc} ({self.timeframe_hours}h)")
        else:
            # Fallback to default yesterday's data for backward compatibility
            yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
            from_date = yesterday.strftime('%Y-%m-%dT00:00:00')
            to_date = yesterday.strftime('%Y-%m-%dT23:59:59')
            timeframe_desc = "Last 24 Hours (Default Fallback)"
            logger.info("Using FALLBACK timeframe: Last 24 Hours")
            logger.info("No custom timeframe configuration detected")
            print(f"🕐 Using default timeframe: Last 24 Hours")
        
        logger.info("=" * 50)
        logger.info(f"FINAL QUERY TIMEFRAME:")
        logger.info(f"  Description: {timeframe_desc}")
        logger.info(f"  From: {from_date}")
        logger.info(f"  To: {to_date}")
        logger.info(f"  Duration: {getattr(self, 'timeframe_hours', 24)} hours")
        logger.info("Enhanced timeframe configuration system ACTIVE")
        logger.info("=" * 50)

        # OpenSearch query to get alert data
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": from_date,
                                    "lte": to_date
                                }
                            }
                        }
                    ]
                }
            },
            "size": 10000,
            "_source": [
                "data.srcip",
                "GeoLocation.country_name", 
                "data.id",
                "data.protocol",
                "data.url",
                "data.browser",
                "full_log",
                "agent.ip",
                "agent.name",
                "rule.id",
                "rule.level",
                "rule.mitre.id",
                "rule.description",
                "rule.mitre.technique"
            ]
        }

        try:
            opensearch_endpoint = f"{self.opensearch_url}/wazuh-alerts-*/_search"
            logger.info(f"Executing OpenSearch query against {opensearch_endpoint}")
            logger.debug(f"Query parameters: size={query['size']}")
            logger.debug(f"Authentication: Basic auth with user {self.opensearch_username}")
            
            # Enhanced request with better error context
            try:
                response = requests.post(
                    opensearch_endpoint,
                    headers=headers,
                    json=query,
                    verify=False,
                    timeout=60
                )
                
                logger.debug(f"OpenSearch response status: {response.status_code}")
                logger.debug(f"Response headers: {dict(response.headers)}")
                
                # Check for specific HTTP status codes before raising
                if response.status_code == 413:
                    logger.error("Request entity too large - query size may be too big")
                    logger.error(f"Current query size: {query.get('size', 'unknown')}")
                    logger.error("Try reducing the query size or implementing pagination")
                    return None
                elif response.status_code == 429:
                    logger.error("Rate limit exceeded - too many requests to OpenSearch")
                    logger.error("Wait before retrying or reduce query frequency")
                    return None
                
                response.raise_for_status()
                
            except requests.exceptions.ChunkedEncodingError as e:
                logger.error(f"Chunked encoding error during OpenSearch request: {e}")
                logger.error("This may indicate network issues or server problems")
                logger.error("Try reducing query size or check network stability")
                return None
            except requests.exceptions.ContentDecodingError as e:
                logger.error(f"Content decoding error during OpenSearch request: {e}")
                logger.error("Response content may be corrupted or in unexpected format")
                return None

            # Enhanced JSON parsing with error handling
            try:
                data = response.json()
            except ValueError as e:
                logger.error(f"Invalid JSON response from OpenSearch: {e}")
                logger.error(f"Response status: {response.status_code}")
                logger.error(f"Response headers: {dict(response.headers)}")
                logger.error(f"Response content (first 500 chars): {response.text[:500]}")
                logger.error("OpenSearch may be returning HTML error page or malformed JSON")
                return None
            except Exception as e:
                logger.error(f"Unexpected error parsing OpenSearch response: {e}")
                logger.error(f"Response status: {response.status_code}")
                logger.error(f"Response size: {len(response.content)} bytes")
                return None
            
            # Enhanced validation of OpenSearch response structure
            if not isinstance(data, dict):
                logger.error("OpenSearch returned invalid response format (not a JSON object)")
                logger.error(f"Response type: {type(data)}")
                logger.error("Expected JSON object with 'hits' field")
                return None
            
            if 'hits' not in data:
                logger.error("OpenSearch response missing 'hits' field")
                logger.error(f"Available fields: {list(data.keys())}")
                logger.error("This may indicate an OpenSearch query error or version incompatibility")
                return None
            
            hits_data = data.get('hits', {})
            if not isinstance(hits_data, dict):
                logger.error("OpenSearch 'hits' field is not a JSON object")
                logger.error(f"Hits type: {type(hits_data)}")
                return None
            
            hits = hits_data.get('hits', [])
            total_hits = hits_data.get('total', {})
            
            # Validate hits structure
            if not isinstance(hits, list):
                logger.error("OpenSearch 'hits.hits' field is not a list")
                logger.error(f"Hits type: {type(hits)}")
                return None
            
            logger.info(f"OpenSearch query returned {len(hits)} alert records")
            if isinstance(total_hits, dict):
                total_value = total_hits.get('value', 'unknown')
                total_relation = total_hits.get('relation', 'eq')
                logger.info(f"Total alerts available: {total_value} ({total_relation})")
            else:
                logger.info(f"Total alerts available: {total_hits}")
            
            logger.debug(f"Query execution time: {data.get('took', 'unknown')} ms")
            
            # Handle empty results case with comprehensive edge case analysis
            if len(hits) == 0:
                logger.warning("No alert data found in OpenSearch query results")
                
                # Use enhanced empty results handler
                query_context = {
                    'from_date': from_date,
                    'to_date': to_date,
                    'size': query.get('size', 'unknown'),
                    'index': 'wazuh-alerts-*',
                    'total_available': total_hits,
                    'query_took_ms': data.get('took', 'unknown')
                }
                
                is_acceptable = self._handle_empty_opensearch_results(query_context)
                
                if not is_acceptable:
                    logger.error("Empty results analysis indicates potential system issues")
                    logger.error("Aborting CSV generation due to suspicious empty results")
                    return None
                
                logger.info("Empty results analysis completed - proceeding with empty CSV generation")
                
                # Additional validation for empty results edge cases
                empty_validation = self._validate_empty_results_edge_cases(query_context)
                if not empty_validation['success']:
                    logger.error("Empty results validation failed")
                    for error in empty_validation['errors']:
                        logger.error(f"Empty results error: {error}")
                    return None

            # Generate enhanced CSV filename with timeframe information
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')
            
            # Create descriptive filename based on timeframe
            if hasattr(self, 'timeframe_hours') and self.timeframe_hours:
                if self.timeframe_hours == 1:
                    timeframe_suffix = "1h"
                elif self.timeframe_hours == 6:
                    timeframe_suffix = "6h"
                elif self.timeframe_hours == 12:
                    timeframe_suffix = "12h"
                elif self.timeframe_hours == 24:
                    timeframe_suffix = "24h"
                elif self.timeframe_hours == 72:
                    timeframe_suffix = "3d"
                elif self.timeframe_hours == 168:
                    timeframe_suffix = "7d"
                elif self.timeframe_hours == 720:
                    timeframe_suffix = "30d"
                else:
                    timeframe_suffix = f"{self.timeframe_hours}h"
            else:
                timeframe_suffix = "24h"  # Default
            
            filename = f"{self.report_title}_{timeframe_suffix}_{timestamp}.csv"
            full_file_path = os.path.join(self.output_directory, filename)
            
            logger.info(f"Enhanced filename generation:")
            logger.info(f"  - Timeframe: {timeframe_suffix}")
            logger.info(f"  - Timestamp: {timestamp}")
            logger.info(f"  - Filename: {filename}")
            logger.info(f"  - Full path: {full_file_path}")
            
            logger.info(f"Writing CSV report to: {full_file_path}")
            logger.debug(f"CSV filename: {filename}")

            try:
                logger.info("Opening CSV file for writing")
                
                # Pre-flight check: ensure we can write to the file location
                try:
                    # Test write access by creating a temporary file in the same directory
                    test_file = full_file_path + '.tmp'
                    with open(test_file, 'w') as test:
                        test.write('test')
                    os.remove(test_file)
                    logger.debug("Write access confirmed for output location")
                except Exception as e:
                    logger.error(f"Cannot write to output location {full_file_path}: {e}")
                    logger.error("Check directory permissions and available space")
                    return None
                
                with open(full_file_path, 'w', newline='', encoding='utf-8') as csvfile:
                    if hits:
                        logger.info(f"Processing {len(hits)} alert records")
                        
                        # Validate first hit structure before processing
                        try:
                            first_hit = hits[0]
                            if not isinstance(first_hit, dict):
                                logger.error(f"Invalid hit structure: expected dict, got {type(first_hit)}")
                                return None
                            
                            if '_source' not in first_hit:
                                logger.error("Hit missing '_source' field")
                                logger.error(f"Available fields in hit: {list(first_hit.keys())}")
                                return None
                            
                            source_data = first_hit['_source']
                            if not isinstance(source_data, dict):
                                logger.error(f"Invalid _source structure: expected dict, got {type(source_data)}")
                                return None
                            
                            fieldnames = self._flatten_keys(source_data)
                            logger.info(f"CSV will contain {len(fieldnames)} columns")
                            logger.debug(f"Column names: {', '.join(fieldnames[:10])}{'...' if len(fieldnames) > 10 else ''}")
                            
                        except (IndexError, KeyError, TypeError) as e:
                            logger.error(f"Error analyzing hit structure: {e}")
                            logger.error("Using fallback standard headers for CSV")
                            fieldnames = self._get_standard_csv_headers()

                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        logger.debug("CSV headers written")

                        # Process records with enhanced error handling
                        processed_count = 0
                        error_count = 0
                        
                        for i, hit in enumerate(hits):
                            try:
                                # Validate individual hit structure
                                if not isinstance(hit, dict) or '_source' not in hit:
                                    logger.warning(f"Skipping invalid hit at index {i}: missing _source")
                                    error_count += 1
                                    continue
                                
                                source_data = hit['_source']
                                if not isinstance(source_data, dict):
                                    logger.warning(f"Skipping invalid hit at index {i}: _source is not a dict")
                                    error_count += 1
                                    continue
                                
                                flattened_row = self._flatten_dict(source_data)
                                writer.writerow(flattened_row)
                                processed_count += 1
                                
                                # Log progress for large datasets
                                if processed_count % 1000 == 0:
                                    logger.debug(f"Processed {processed_count}/{len(hits)} records")
                                    
                            except Exception as e:
                                logger.warning(f"Error processing hit at index {i}: {e}")
                                logger.debug(f"Problematic hit data: {hit}")
                                error_count += 1
                                continue
                        
                        logger.info(f"Successfully processed {processed_count} alert records")
                        if error_count > 0:
                            logger.warning(f"Encountered {error_count} errors while processing hits")
                            logger.warning("Some records may have been skipped due to data format issues")
                        
                    else:
                        logger.warning("No alert data found, creating empty CSV with standard headers")
                        
                        # Create empty CSV with standard headers - enhanced for edge cases
                        fieldnames = self._get_standard_csv_headers()
                        logger.info(f"Using standard CSV headers: {len(fieldnames)} columns")
                        logger.debug(f"Standard headers: {', '.join(fieldnames[:5])}{'...' if len(fieldnames) > 5 else ''}")
                        
                        # Validate headers before writing
                        header_validation = self._validate_csv_headers_for_empty_data(fieldnames)
                        if not header_validation['success']:
                            logger.error("CSV header validation failed for empty data")
                            for error in header_validation['errors']:
                                logger.error(f"Header validation error: {error}")
                            return None
                        
                        # Log header validation warnings
                        for warning in header_validation['warnings']:
                            logger.warning(f"Header validation warning: {warning}")
                        
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        
                        try:
                            writer.writeheader()
                            logger.info("Empty CSV with standard headers created successfully")
                            
                            # Enhanced verification for empty CSV edge cases
                            csvfile.flush()  # Ensure data is written to disk
                            current_pos = csvfile.tell()
                            if current_pos > 0:
                                logger.debug(f"CSV header size: {current_pos} bytes")
                                
                                # Additional validation: try to read back the headers
                                try:
                                    csvfile.seek(0)
                                    first_line = csvfile.readline().strip()
                                    if first_line:
                                        header_count = len(first_line.split(','))
                                        if header_count == len(fieldnames):
                                            logger.debug(f"Header verification successful: {header_count} columns")
                                        else:
                                            logger.warning(f"Header count mismatch: expected {len(fieldnames)}, got {header_count}")
                                    else:
                                        logger.error("Could not read back written headers")
                                        return None
                                except Exception as verify_error:
                                    logger.warning(f"Could not verify written headers: {verify_error}")
                                
                                # Reset file position for any subsequent operations
                                csvfile.seek(0, 2)  # Seek to end
                            else:
                                logger.error("CSV file appears empty after writing headers")
                                logger.error("This indicates a write failure or file system issue")
                                return None
                                
                        except Exception as e:
                            logger.error(f"Error writing CSV headers: {e}")
                            logger.error("Failed to create empty CSV file")
                            logger.error(f"Error type: {type(e).__name__}")
                            
                            # Enhanced error context for empty CSV creation
                            logger.error("Empty CSV creation troubleshooting:")
                            logger.error(f"  - File path: {full_file_path}")
                            logger.error(f"  - Headers count: {len(fieldnames)}")
                            logger.error(f"  - Directory writable: {os.access(self.output_directory, os.W_OK)}")
                            logger.error(f"  - Available disk space: {self._check_disk_space()}")
                            
                            return None

                # Enhanced file verification with comprehensive checks
                if os.path.exists(full_file_path):
                    try:
                        file_size = os.path.getsize(full_file_path)
                        logger.info(f"CSV report successfully generated: {full_file_path}")
                        logger.info(f"File size: {file_size} bytes, Records: {len(hits)}")
                        
                        # Additional file integrity checks
                        if file_size == 0:
                            logger.error("CSV file was created but is empty")
                            logger.error("This indicates a write failure or disk space issue")
                            return None
                        
                        # Verify file is readable
                        if not os.access(full_file_path, os.R_OK):
                            logger.error("CSV file was created but is not readable")
                            logger.error("Check file permissions")
                            return None
                        
                        # Quick validation that file contains expected content
                        try:
                            with open(full_file_path, 'r', encoding='utf-8') as verify_file:
                                first_line = verify_file.readline().strip()
                                if not first_line:
                                    logger.error("CSV file appears to be empty (no header line)")
                                    return None
                                
                                # Count lines for verification
                                verify_file.seek(0)
                                line_count = sum(1 for _ in verify_file)
                                expected_lines = len(hits) + 1  # +1 for header
                                
                                if line_count != expected_lines:
                                    logger.warning(f"CSV line count mismatch: expected {expected_lines}, got {line_count}")
                                    logger.warning("Some records may not have been written correctly")
                                else:
                                    logger.debug(f"CSV line count verified: {line_count} lines")
                                
                        except Exception as verify_error:
                            logger.warning(f"Could not verify CSV content: {verify_error}")
                            logger.warning("File was created but content verification failed")
                        
                        logger.debug(f"CSV generation completed in {datetime.datetime.now() - start_time}")
                        return full_file_path
                        
                    except OSError as e:
                        logger.error(f"Error verifying created CSV file: {e}")
                        logger.error(f"File exists but cannot be accessed: {full_file_path}")
                        return None
                else:
                    logger.error(f"CSV file was not created at expected location: {full_file_path}")
                    logger.error("File system may have failed to write the file")
                    logger.error("Possible causes:")
                    logger.error("  - Insufficient disk space during write operation")
                    logger.error("  - File system errors or corruption")
                    logger.error("  - Antivirus software blocking file creation")
                    logger.error("  - Directory permissions changed during operation")
                    logger.error(f"  - Target directory: {self.output_directory}")
                    return None

            except PermissionError as e:
                logger.error(f"Permission error writing CSV file {full_file_path}: {e}")
                logger.error(f"Error details: {str(e)}")
                logger.error("Troubleshooting suggestions:")
                logger.error("  - Check file permissions and ensure the directory is writable")
                logger.error("  - Verify user has write access to the target directory")
                logger.error("  - Run with appropriate permissions (sudo if needed)")
                logger.error(f"  - Target directory: {self.output_directory}")
                return None
            except OSError as e:
                logger.error(f"OS error writing CSV file {full_file_path}: {e}")
                logger.error(f"Error code: {e.errno}")
                logger.error(f"Error details: {str(e)}")
                
                if e.errno == 28:  # No space left on device
                    logger.error("No space left on device")
                    logger.error("Free up disk space or choose a different output location")
                elif e.errno == 36:  # File name too long
                    logger.error("File name too long")
                    logger.error("Use a shorter path or move to a different location")
                elif e.errno == 13:  # Permission denied
                    logger.error("Permission denied")
                    logger.error("Check directory permissions and user access rights")
                elif e.errno == 17:  # File exists
                    logger.error("File exists (but cannot be overwritten)")
                    logger.error("Remove the existing file or choose a different filename")
                else:
                    logger.error(f"System error occurred (errno: {e.errno})")
                    logger.error("Check system logs for more details")
                
                logger.error(f"Failed file path: {full_file_path}")
                logger.error(f"Target directory: {self.output_directory}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error writing CSV file {full_file_path}: {e}")
                logger.error(f"Error type: {type(e).__name__}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return None

        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error executing OpenSearch query: {e}")
            logger.error(f"Status code: {e.response.status_code}")
            logger.error(f"OpenSearch endpoint: {opensearch_endpoint}")
            
            if e.response.status_code == 401:
                logger.error("OpenSearch authentication failed - Invalid credentials")
                logger.error("Check OpenSearch username and password")
                logger.error(f"Username used: {self.opensearch_username}")
                logger.error("Verify credentials can access OpenSearch")
            elif e.response.status_code == 403:
                logger.error("OpenSearch access forbidden - User may not have required permissions")
                logger.error("Check user permissions for wazuh-alerts-* indices")
            elif e.response.status_code == 404:
                logger.error("OpenSearch endpoint or index not found")
                logger.error(f"Check OpenSearch URL: {self.opensearch_url}")
                logger.error("Verify wazuh-alerts-* indices exist")
            elif e.response.status_code >= 500:
                logger.error("OpenSearch server error - Check OpenSearch service status")
            
            try:
                error_response = e.response.json()
                logger.error(f"Error response details: {error_response}")
            except:
                logger.error(f"Error response text: {e.response.text}")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error executing OpenSearch query: {e}")
            logger.error(f"Failed to connect to: {opensearch_endpoint}")
            logger.error("Check network connectivity and OpenSearch service status")
            logger.error("Verify OpenSearch URL is correct and accessible")
            logger.error(f"OpenSearch URL: {self.opensearch_url}")
            
            # Handle test mode with mock data when OpenSearch is unavailable
            if self.test_mode:
                logger.warning("OpenSearch connection failed in test mode - generating mock data")
                return self._generate_mock_csv_report()
            
            return None
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout error executing OpenSearch query: {e}")
            logger.error("OpenSearch query timed out after 60 seconds")
            logger.error("Check network latency and OpenSearch server performance")
            logger.error("Consider reducing query size or increasing timeout")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error executing OpenSearch query: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error("Check network configuration and proxy settings")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"HTTP Status Code: {e.response.status_code}")
                try:
                    error_details = e.response.json()
                    logger.error(f"Error details: {error_details}")
                except:
                    logger.error(f"Response text: {e.response.text}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during CSV report generation: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            logger.error(f"Query parameters: from_date={from_date}, to_date={to_date}")
            logger.error(f"OpenSearch endpoint: {opensearch_endpoint}")
            return None

    def _flatten_dict(self, d, parent_key='', sep='.'):
        """Flatten nested dictionary for CSV output"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Convert list to string representation
                items.append((new_key, ', '.join(map(str, v)) if v else ''))
            else:
                items.append((new_key, v))
        return dict(items)

    def _flatten_keys(self, d, parent_key='', sep='.'):
        """Get flattened keys from nested dictionary"""
        keys = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                keys.extend(self._flatten_keys(v, new_key, sep=sep))
            else:
                keys.append(new_key)
        return keys

    def _get_standard_csv_headers(self):
        """
        Get standard CSV headers for Wazuh security alerts
        
        Returns:
            list: Standard field names for CSV output
        """
        return [
            'data.srcip', 'GeoLocation.country_name', 'data.id',
            'data.protocol', 'data.url', 'data.browser', 'full_log',
            'agent.ip', 'agent.name', 'rule.id', 'rule.level',
            'rule.mitre.id', 'rule.description', 'rule.mitre.technique'
        ]

    def _generate_mock_csv_report(self):
        """
        Generate a mock CSV report for testing when OpenSearch is unavailable
        
        Returns:
            str: Full path to the generated mock CSV file, or None if failed
        """
        logger.info("Generating mock CSV report for test mode")
        logger.info("This is used when OpenSearch is unavailable in test mode")
        
        try:
            # Create output directory if needed
            if not self.create_output_directory():
                logger.error("Failed to create output directory for mock CSV")
                return None
            
            # Check disk space before generating mock data
            if not self._check_disk_space():
                logger.error("Insufficient disk space for mock CSV generation")
                return None
            
            # Generate enhanced test filename with timeframe information
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')
            
            # Create descriptive test filename based on timeframe
            if hasattr(self, 'timeframe_hours') and self.timeframe_hours:
                if self.timeframe_hours == 1:
                    timeframe_suffix = "1h"
                elif self.timeframe_hours == 6:
                    timeframe_suffix = "6h"
                elif self.timeframe_hours == 12:
                    timeframe_suffix = "12h"
                elif self.timeframe_hours == 24:
                    timeframe_suffix = "24h"
                elif self.timeframe_hours == 72:
                    timeframe_suffix = "3d"
                elif self.timeframe_hours == 168:
                    timeframe_suffix = "7d"
                elif self.timeframe_hours == 720:
                    timeframe_suffix = "30d"
                else:
                    timeframe_suffix = f"{self.timeframe_hours}h"
            else:
                timeframe_suffix = "24h"  # Default
            
            filename = f"TEST_{self.report_title}_{timeframe_suffix}_{timestamp}.csv"
            full_file_path = os.path.join(self.output_directory, filename)
            
            logger.info(f"Enhanced TEST filename generation:")
            logger.info(f"  - Test mode: ACTIVE")
            logger.info(f"  - Timeframe: {timeframe_suffix}")
            logger.info(f"  - Timestamp: {timestamp}")
            logger.info(f"  - Filename: {filename}")
            logger.info(f"  - Full path: {full_file_path}")
            
            logger.info(f"Creating mock CSV file: {full_file_path}")
            
            # Mock alert data for testing
            mock_alerts = [
                {
                    'data.srcip': '192.168.1.100',
                    'GeoLocation.country_name': 'United States',
                    'data.id': '12345',
                    'data.protocol': 'TCP',
                    'data.url': '/admin/login',
                    'data.browser': 'Mozilla/5.0',
                    'full_log': 'Mock security alert for testing purposes',
                    'agent.ip': '10.0.0.5',
                    'agent.name': 'test-server-01',
                    'rule.id': '31100',
                    'rule.level': '10',
                    'rule.mitre.id': 'T1078',
                    'rule.description': 'Mock brute force attack detected',
                    'rule.mitre.technique': 'Valid Accounts'
                },
                {
                    'data.srcip': '203.0.113.45',
                    'GeoLocation.country_name': 'Unknown',
                    'data.id': '12346',
                    'data.protocol': 'HTTP',
                    'data.url': '/api/v1/users',
                    'data.browser': 'curl/7.68.0',
                    'full_log': 'Mock API access attempt from suspicious IP',
                    'agent.ip': '10.0.0.10',
                    'agent.name': 'api-server-02',
                    'rule.id': '31200',
                    'rule.level': '8',
                    'rule.mitre.id': 'T1190',
                    'rule.description': 'Mock suspicious API access',
                    'rule.mitre.technique': 'Exploit Public-Facing Application'
                },
                {
                    'data.srcip': '198.51.100.25',
                    'GeoLocation.country_name': 'Canada',
                    'data.id': '12347',
                    'data.protocol': 'SSH',
                    'data.url': '',
                    'data.browser': '',
                    'full_log': 'Mock SSH login failure from external IP',
                    'agent.ip': '10.0.0.15',
                    'agent.name': 'ssh-gateway-01',
                    'rule.id': '5716',
                    'rule.level': '5',
                    'rule.mitre.id': 'T1110',
                    'rule.description': 'Mock SSH authentication failure',
                    'rule.mitre.technique': 'Brute Force'
                }
            ]
            
            logger.info(f"Generating mock CSV with {len(mock_alerts)} test records")
            
            try:
                with open(full_file_path, 'w', newline='', encoding='utf-8') as csvfile:
                    # Get headers from mock data
                    fieldnames = list(mock_alerts[0].keys())
                    logger.debug(f"Mock CSV headers: {fieldnames}")
                    
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    # Write mock data records
                    for i, alert in enumerate(mock_alerts):
                        try:
                            writer.writerow(alert)
                        except Exception as e:
                            logger.warning(f"Error writing mock alert {i}: {e}")
                            continue
                    
                    # Add test mode indicator comment (as a row with all fields empty except first)
                    test_indicator = {field: '' for field in fieldnames}
                    test_indicator[fieldnames[0]] = '# TEST MODE DATA - Generated for testing purposes'
                    writer.writerow(test_indicator)
                    
                logger.info(f"Mock CSV report generated successfully: {full_file_path}")
                
                # Verify file was created and has content
                if os.path.exists(full_file_path):
                    file_size = os.path.getsize(full_file_path)
                    logger.info(f"Mock CSV file size: {file_size} bytes")
                    
                    if file_size == 0:
                        logger.error("Mock CSV file was created but is empty")
                        return None
                    
                    logger.info("Mock CSV generation completed successfully")
                    return full_file_path
                else:
                    logger.error("Mock CSV file was not created")
                    return None
                    
            except PermissionError as e:
                logger.error(f"Permission error creating mock CSV: {e}")
                logger.error("Check directory permissions for mock file creation")
                return None
            except OSError as e:
                logger.error(f"OS error creating mock CSV: {e}")
                logger.error(f"Error code: {e.errno}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error creating mock CSV: {e}")
                logger.error(f"Error type: {type(e).__name__}")
                return None
                
        except Exception as e:
            logger.error(f"Critical error in mock CSV generation: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    def _handle_empty_opensearch_results(self, query_params=None):
        """
        Handle empty OpenSearch results with comprehensive logging and validation
        
        Args:
            query_params (dict): Optional query parameters for context
            
        Returns:
            bool: True if empty results are acceptable, False if it indicates an error
        """
        logger.info("Analyzing empty OpenSearch results")
        
        # Log query context if available
        if query_params:
            logger.info("Query context:")
            logger.info(f"  - Date range: {query_params.get('from_date', 'unknown')} to {query_params.get('to_date', 'unknown')}")
            logger.info(f"  - Query size limit: {query_params.get('size', 'unknown')}")
            logger.info(f"  - Index pattern: {query_params.get('index', 'wazuh-alerts-*')}")
        
        # Check if this is expected (no alerts in time range) vs. a system issue
        logger.info("Empty results analysis:")
        logger.info("This could indicate:")
        logger.info("  ✅ Normal: No security alerts in the specified time range")
        logger.info("  ✅ Normal: Alerts exist but don't match query criteria")
        logger.info("  ⚠️  Possible issue: Wazuh indexing delays or problems")
        logger.info("  ⚠️  Possible issue: OpenSearch index configuration problems")
        logger.info("  ⚠️  Possible issue: Query syntax or field mapping issues")
        
        # Provide troubleshooting guidance
        logger.info("Troubleshooting empty results:")
        logger.info("  1. Check if Wazuh agents are active and sending data")
        logger.info("  2. Verify OpenSearch indices exist: wazuh-alerts-*")
        logger.info("  3. Check index patterns and field mappings")
        logger.info("  4. Verify time range covers expected alert periods")
        logger.info("  5. Check Wazuh manager and indexer connectivity")
        logger.info("  6. Review Wazuh rules and alert generation")
        
        # In test mode, empty results are more acceptable
        if self.test_mode:
            logger.info("Test mode: Empty results are acceptable for testing")
            logger.info("Will proceed to create empty CSV with standard headers")
            return True
        
        # In production, log additional context
        logger.warning("Production mode: Empty results may indicate system issues")
        logger.warning("Monitor system health and alert generation")
        logger.warning("Consider investigating if this persists")
        
        return True  # Allow processing to continue with empty CSV

    def _validate_empty_results_edge_cases(self, query_context):
        """
        Validate empty OpenSearch results for potential edge cases and system issues
        
        Args:
            query_context (dict): Query context information
            
        Returns:
            dict: Validation result with success status and error details
        """
        validation_result = {
            'success': True,
            'errors': [],
            'warnings': [],
            'analysis': {}
        }
        
        logger.info("Performing comprehensive empty results edge case validation")
        
        try:
            # Analyze query parameters for potential issues
            from_date = query_context.get('from_date', '')
            to_date = query_context.get('to_date', '')
            query_size = query_context.get('size', 0)
            total_available = query_context.get('total_available', {})
            query_took_ms = query_context.get('query_took_ms', 'unknown')
            
            validation_result['analysis']['query_parameters'] = {
                'date_range': f"{from_date} to {to_date}",
                'size_limit': query_size,
                'execution_time_ms': query_took_ms
            }
            
            # Check for suspicious query execution times
            if isinstance(query_took_ms, (int, float)):
                if query_took_ms < 1:
                    validation_result['warnings'].append(
                        f"Query executed very quickly ({query_took_ms}ms) - may indicate index issues"
                    )
                elif query_took_ms > 30000:  # 30 seconds
                    validation_result['warnings'].append(
                        f"Query took very long ({query_took_ms}ms) - may indicate performance issues"
                    )
                
                validation_result['analysis']['performance'] = {
                    'execution_time_ms': query_took_ms,
                    'performance_category': 'fast' if query_took_ms < 100 else 'normal' if query_took_ms < 5000 else 'slow'
                }
            
            # Analyze total hits information for edge cases
            if isinstance(total_available, dict):
                total_value = total_available.get('value', 0)
                total_relation = total_available.get('relation', 'eq')
                
                validation_result['analysis']['total_hits'] = {
                    'value': total_value,
                    'relation': total_relation
                }
                
                # Check for suspicious total counts
                if total_value == 0 and total_relation == 'eq':
                    logger.info("Confirmed: No documents match the query criteria")
                elif total_value > 0 and total_relation == 'gte':
                    validation_result['warnings'].append(
                        f"Total hits shows {total_value}+ available but query returned 0 - possible pagination issue"
                    )
                elif total_value > query_size:
                    validation_result['warnings'].append(
                        f"More documents available ({total_value}) than query size ({query_size}) - results may be truncated"
                    )
            
            # Validate date range for potential issues
            try:
                from datetime import datetime
                if from_date and to_date:
                    # Parse dates to check for edge cases
                    from_dt = datetime.fromisoformat(from_date.replace('T', ' ').replace('Z', ''))
                    to_dt = datetime.fromisoformat(to_date.replace('T', ' ').replace('Z', ''))
                    
                    # Check if date range is in the future
                    now = datetime.now()
                    if from_dt > now:
                        validation_result['warnings'].append(
                            "Query date range is in the future - no alerts expected"
                        )
                    
                    # Check if date range is very old
                    days_ago = (now - to_dt).days
                    if days_ago > 365:
                        validation_result['warnings'].append(
                            f"Query date range is very old ({days_ago} days ago) - data may be archived"
                        )
                    
                    # Check if date range is very narrow
                    range_hours = (to_dt - from_dt).total_seconds() / 3600
                    if range_hours < 1:
                        validation_result['warnings'].append(
                            f"Query date range is very narrow ({range_hours:.1f} hours) - may miss alerts"
                        )
                    
                    validation_result['analysis']['date_range'] = {
                        'from_date': from_dt.isoformat(),
                        'to_date': to_dt.isoformat(),
                        'range_hours': round(range_hours, 2),
                        'days_ago': days_ago
                    }
                    
            except (ValueError, TypeError) as e:
                validation_result['warnings'].append(f"Could not parse date range for analysis: {e}")
            
            # Check for potential index-related issues
            index_pattern = query_context.get('index', 'wazuh-alerts-*')
            if '*' in index_pattern:
                validation_result['warnings'].append(
                    f"Using wildcard index pattern '{index_pattern}' - verify indices exist for date range"
                )
            
            # Log validation summary
            logger.info("Empty results validation summary:")
            logger.info(f"  - Errors: {len(validation_result['errors'])}")
            logger.info(f"  - Warnings: {len(validation_result['warnings'])}")
            
            if validation_result['warnings']:
                logger.info("Empty results warnings:")
                for warning in validation_result['warnings']:
                    logger.warning(f"  - {warning}")
            
            # Determine if empty results are acceptable
            critical_errors = [
                error for error in validation_result['errors'] 
                if 'critical' in error.lower() or 'fatal' in error.lower()
            ]
            
            if critical_errors:
                validation_result['success'] = False
                logger.error("Critical issues detected in empty results analysis")
            else:
                logger.info("Empty results validation passed - no critical issues detected")
            
            return validation_result
            
        except Exception as e:
            error_msg = f"Unexpected error during empty results validation: {e}"
            logger.error(f"Empty results validation error: {error_msg}")
            logger.error(f"Error type: {type(e).__name__}")
            validation_result['errors'].append(error_msg)
            validation_result['success'] = False
            return validation_result

    def _validate_csv_headers_for_empty_data(self, headers):
        """
        Validate CSV headers when no data is available to ensure proper structure
        
        Args:
            headers (list): List of header field names
            
        Returns:
            dict: Validation result with success status and details
        """
        validation_result = {
            'success': False,
            'header_count': 0,
            'missing_standard_fields': [],
            'extra_fields': [],
            'errors': [],
            'warnings': []
        }
        
        logger.info("Validating CSV headers for empty data scenario")
        
        try:
            if not headers:
                error_msg = "No headers provided for validation"
                logger.error(f"Header validation error: {error_msg}")
                validation_result['errors'].append(error_msg)
                return validation_result
            
            if not isinstance(headers, list):
                error_msg = f"Headers must be a list, got {type(headers)}"
                logger.error(f"Header validation error: {error_msg}")
                validation_result['errors'].append(error_msg)
                return validation_result
            
            validation_result['header_count'] = len(headers)
            logger.info(f"Validating {len(headers)} CSV headers")
            
            # Check for empty or invalid header names
            invalid_headers = []
            for i, header in enumerate(headers):
                if not header or not isinstance(header, str):
                    invalid_headers.append(f"Header {i}: '{header}'")
                elif header.strip() != header:
                    validation_result['warnings'].append(f"Header has leading/trailing whitespace: '{header}'")
                elif len(header) > 100:  # Reasonable header length limit
                    validation_result['warnings'].append(f"Header is very long ({len(header)} chars): '{header[:50]}...'")
            
            if invalid_headers:
                error_msg = f"Invalid header names found: {', '.join(invalid_headers[:3])}"
                logger.error(f"Header validation error: {error_msg}")
                validation_result['errors'].append(error_msg)
                return validation_result
            
            # Check for duplicate headers
            duplicate_headers = []
            seen_headers = set()
            for header in headers:
                if header in seen_headers:
                    duplicate_headers.append(header)
                seen_headers.add(header)
            
            if duplicate_headers:
                error_msg = f"Duplicate headers found: {', '.join(duplicate_headers)}"
                logger.error(f"Header validation error: {error_msg}")
                validation_result['errors'].append(error_msg)
                return validation_result
            
            # Compare with expected standard headers
            standard_headers = self._get_standard_csv_headers()
            
            # Find missing standard fields
            for standard_header in standard_headers:
                if standard_header not in headers:
                    validation_result['missing_standard_fields'].append(standard_header)
            
            # Find extra fields (not in standard set)
            for header in headers:
                if header not in standard_headers:
                    validation_result['extra_fields'].append(header)
            
            # Log validation results
            if validation_result['missing_standard_fields']:
                warning_msg = f"Missing {len(validation_result['missing_standard_fields'])} standard fields"
                logger.warning(f"Header validation: {warning_msg}")
                validation_result['warnings'].append(warning_msg)
                logger.debug(f"Missing fields: {', '.join(validation_result['missing_standard_fields'][:5])}")
            
            if validation_result['extra_fields']:
                info_msg = f"Found {len(validation_result['extra_fields'])} additional fields"
                logger.info(f"Header validation: {info_msg}")
                logger.debug(f"Extra fields: {', '.join(validation_result['extra_fields'][:5])}")
            
            # Validation successful if no critical errors
            validation_result['success'] = True
            logger.info("CSV header validation completed successfully")
            logger.info(f"Header validation summary:")
            logger.info(f"  - Total headers: {validation_result['header_count']}")
            logger.info(f"  - Missing standard: {len(validation_result['missing_standard_fields'])}")
            logger.info(f"  - Extra fields: {len(validation_result['extra_fields'])}")
            logger.info(f"  - Warnings: {len(validation_result['warnings'])}")
            
            return validation_result
            
        except Exception as e:
            error_msg = f"Unexpected error during header validation: {e}"
            logger.error(f"Header validation error: {error_msg}")
            logger.error(f"Error type: {type(e).__name__}")
            validation_result['errors'].append(error_msg)
            return validation_result

    def _handle_filesystem_edge_cases(self, file_path, operation="write"):
        """
        Handle file system edge cases with comprehensive error checking
        
        Args:
            file_path (str): Path to the file being operated on
            operation (str): Type of operation ("write", "read", "delete")
            
        Returns:
            dict: Result with success status and detailed error information
        """
        result = {
            'success': False,
            'file_path': file_path,
            'operation': operation,
            'checks_performed': [],
            'errors': [],
            'warnings': [],
            'system_info': {}
        }
        
        logger.info(f"Performing file system edge case analysis for {operation} operation")
        logger.info(f"Target file: {file_path}")
        
        try:
            # Basic path validation
            result['checks_performed'].append('path_validation')
            
            if not file_path or not isinstance(file_path, str):
                error_msg = f"Invalid file path: {file_path}"
                logger.error(f"File system check error: {error_msg}")
                result['errors'].append(error_msg)
                return result
            
            if len(file_path) > 260:  # Windows path length limit
                warning_msg = f"File path is very long ({len(file_path)} chars) - may cause issues on some systems"
                logger.warning(f"File system warning: {warning_msg}")
                result['warnings'].append(warning_msg)
            
            # Directory analysis
            result['checks_performed'].append('directory_analysis')
            directory = os.path.dirname(file_path)
            
            if not directory:
                error_msg = "Cannot determine directory from file path"
                logger.error(f"File system check error: {error_msg}")
                result['errors'].append(error_msg)
                return result
            
            # Check if directory exists
            if not os.path.exists(directory):
                error_msg = f"Directory does not exist: {directory}"
                logger.error(f"File system check error: {error_msg}")
                result['errors'].append(error_msg)
                return result
            
            if not os.path.isdir(directory):
                error_msg = f"Path exists but is not a directory: {directory}"
                logger.error(f"File system check error: {error_msg}")
                result['errors'].append(error_msg)
                return result
            
            # Disk space analysis
            result['checks_performed'].append('disk_space_analysis')
            
            try:
                statvfs = os.statvfs(directory)
                available_bytes = statvfs.f_bavail * statvfs.f_frsize
                total_bytes = statvfs.f_blocks * statvfs.f_frsize
                used_bytes = total_bytes - available_bytes
                
                available_mb = available_bytes / (1024 * 1024)
                total_gb = total_bytes / (1024 * 1024 * 1024)
                used_percent = (used_bytes / total_bytes) * 100 if total_bytes > 0 else 0
                
                result['system_info']['disk_space'] = {
                    'available_mb': round(available_mb, 2),
                    'total_gb': round(total_gb, 2),
                    'used_percent': round(used_percent, 1)
                }
                
                logger.info(f"Disk space analysis:")
                logger.info(f"  - Available: {available_mb:.2f} MB")
                logger.info(f"  - Total: {total_gb:.2f} GB")
                logger.info(f"  - Used: {used_percent:.1f}%")
                
                # Check for low disk space conditions
                if available_mb < 10:  # Less than 10MB
                    error_msg = f"Critical: Very low disk space ({available_mb:.2f} MB available)"
                    logger.error(f"File system check error: {error_msg}")
                    result['errors'].append(error_msg)
                elif available_mb < 100:  # Less than 100MB
                    warning_msg = f"Low disk space warning ({available_mb:.2f} MB available)"
                    logger.warning(f"File system warning: {warning_msg}")
                    result['warnings'].append(warning_msg)
                
                if used_percent > 95:
                    error_msg = f"Critical: Disk usage very high ({used_percent:.1f}%)"
                    logger.error(f"File system check error: {error_msg}")
                    result['errors'].append(error_msg)
                elif used_percent > 90:
                    warning_msg = f"High disk usage warning ({used_percent:.1f}%)"
                    logger.warning(f"File system warning: {warning_msg}")
                    result['warnings'].append(warning_msg)
                
            except OSError as e:
                warning_msg = f"Could not analyze disk space: {e}"
                logger.warning(f"File system warning: {warning_msg}")
                result['warnings'].append(warning_msg)
            
            # Permission analysis
            result['checks_performed'].append('permission_analysis')
            
            if operation in ["write", "delete"]:
                if not os.access(directory, os.W_OK):
                    error_msg = f"No write permission for directory: {directory}"
                    logger.error(f"File system check error: {error_msg}")
                    result['errors'].append(error_msg)
                    return result
            
            if operation == "read":
                if os.path.exists(file_path):
                    if not os.access(file_path, os.R_OK):
                        error_msg = f"No read permission for file: {file_path}"
                        logger.error(f"File system check error: {error_msg}")
                        result['errors'].append(error_msg)
                        return result
                else:
                    error_msg = f"File does not exist for read operation: {file_path}"
                    logger.error(f"File system check error: {error_msg}")
                    result['errors'].append(error_msg)
                    return result
            
            # File existence analysis
            result['checks_performed'].append('file_existence_analysis')
            
            if os.path.exists(file_path):
                if os.path.isfile(file_path):
                    try:
                        file_size = os.path.getsize(file_path)
                        result['system_info']['existing_file_size'] = file_size
                        logger.info(f"Existing file size: {file_size} bytes")
                        
                        if operation == "write":
                            logger.info("File exists and will be overwritten")
                    except OSError as e:
                        warning_msg = f"Could not get existing file size: {e}"
                        logger.warning(f"File system warning: {warning_msg}")
                        result['warnings'].append(warning_msg)
                else:
                    error_msg = f"Path exists but is not a file: {file_path}"
                    logger.error(f"File system check error: {error_msg}")
                    result['errors'].append(error_msg)
                    return result
            
            # File system type and mount point analysis (if possible)
            result['checks_performed'].append('filesystem_analysis')
            
            try:
                # Try to get file system information
                stat_result = os.statvfs(directory)
                result['system_info']['filesystem'] = {
                    'block_size': stat_result.f_frsize,
                    'total_blocks': stat_result.f_blocks,
                    'free_blocks': stat_result.f_bavail
                }
                
                # Check for potential file system issues
                if stat_result.f_frsize == 0:
                    warning_msg = "Unusual file system block size (0) detected"
                    logger.warning(f"File system warning: {warning_msg}")
                    result['warnings'].append(warning_msg)
                
            except (OSError, AttributeError) as e:
                logger.debug(f"Could not get detailed file system info: {e}")
            
            # All checks passed
            result['success'] = True
            logger.info("File system edge case analysis completed successfully")
            logger.info(f"Checks performed: {', '.join(result['checks_performed'])}")
            logger.info(f"Warnings found: {len(result['warnings'])}")
            
            return result
            
        except Exception as e:
            error_msg = f"Unexpected error during file system analysis: {e}"
            logger.error(f"File system check error: {error_msg}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            result['errors'].append(error_msg)
            return result

    def validate_csv_content(self, filename):
        """
        Validate generated CSV file for existence, structure, and content
        
        Args:
            filename (str): Full path to the CSV file to validate
            
        Returns:
            dict: Validation results containing success status, record count, and details
        """
        validation_result = {
            'success': False,
            'file_exists': False,
            'file_readable': False,
            'has_headers': False,
            'record_count': 0,
            'file_size': 0,
            'headers': [],
            'errors': [],
            'warnings': []
        }
        
        logger.info(f"Starting CSV validation for file: {filename}")
        
        try:
            # Check if file exists
            if not os.path.exists(filename):
                error_msg = f"CSV file does not exist: {filename}"
                logger.error(f"Validation Error: {error_msg}")
                logger.error(f"Expected file location: {filename}")
                logger.error("Check if CSV generation completed successfully")
                validation_result['errors'].append(error_msg)
                return validation_result
            
            validation_result['file_exists'] = True
            logger.debug("CSV file exists - proceeding with validation")
            
            # Check if file is readable
            if not os.access(filename, os.R_OK):
                error_msg = f"CSV file is not readable: {filename}"
                logger.error(f"Validation Error: {error_msg}")
                logger.error("Check file permissions and user access rights")
                validation_result['errors'].append(error_msg)
                return validation_result
            
            validation_result['file_readable'] = True
            logger.debug("CSV file is readable - proceeding with content validation")
            
            # Get file size
            try:
                validation_result['file_size'] = os.path.getsize(filename)
                logger.info(f"CSV file size: {validation_result['file_size']} bytes")
            except OSError as e:
                warning_msg = f"Could not determine file size: {e}"
                logger.warning(f"Validation Warning: {warning_msg}")
                validation_result['warnings'].append(warning_msg)
            
            # Validate CSV structure and content
            try:
                with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
                    # Check if file is empty
                    if validation_result['file_size'] == 0:
                        error_msg = "CSV file is empty"
                        logger.error(f"Validation Error: {error_msg}")
                        logger.error("CSV generation may have failed or no data was available")
                        validation_result['errors'].append(error_msg)
                        return validation_result
                    
                    # Use csv.Sniffer to detect CSV format
                    try:
                        sample = csvfile.read(1024)
                        csvfile.seek(0)
                        sniffer = csv.Sniffer()
                        
                        # Check if it looks like CSV
                        if not sniffer.has_header(sample):
                            warning_msg = "CSV file may not have proper headers"
                            logger.warning(f"Validation Warning: {warning_msg}")
                            validation_result['warnings'].append(warning_msg)
                        
                        # Detect delimiter
                        try:
                            delimiter = sniffer.sniff(sample).delimiter
                            logger.debug(f"Detected CSV delimiter: '{delimiter}'")
                        except csv.Error:
                            delimiter = ','
                            warning_msg = "Could not detect CSV delimiter, using default comma"
                            logger.warning(f"Validation Warning: {warning_msg}")
                            validation_result['warnings'].append(warning_msg)
                        
                    except Exception as e:
                        delimiter = ','
                        warning_msg = f"CSV format detection failed, using default comma: {e}"
                        logger.warning(f"Validation Warning: {warning_msg}")
                        validation_result['warnings'].append(warning_msg)
                    
                    # Reset file pointer and read CSV content
                    csvfile.seek(0)
                    csv_reader = csv.reader(csvfile, delimiter=delimiter)
                    
                    # Read and validate headers
                    try:
                        headers = next(csv_reader)
                        if headers:
                            validation_result['has_headers'] = True
                            validation_result['headers'] = headers
                            logger.info(f"CSV headers found: {len(headers)} columns")
                            logger.debug(f"Header columns: {', '.join(headers[:5])}{'...' if len(headers) > 5 else ''}")
                        else:
                            error_msg = "CSV file has empty header row"
                            logger.error(f"Validation Error: {error_msg}")
                            validation_result['errors'].append(error_msg)
                            return validation_result
                    except StopIteration:
                        error_msg = "CSV file has no content (not even headers)"
                        logger.error(f"Validation Error: {error_msg}")
                        validation_result['errors'].append(error_msg)
                        return validation_result
                    
                    # Count data records (excluding header)
                    record_count = 0
                    row_number = 1  # Start at 1 since we already read the header
                    
                    for row in csv_reader:
                        row_number += 1
                        if row:  # Skip completely empty rows
                            record_count += 1
                            
                            # Validate row structure (should have same number of columns as headers)
                            if len(row) != len(headers):
                                warning_msg = f"Row {row_number} has {len(row)} columns, expected {len(headers)}"
                                validation_result['warnings'].append(warning_msg)
                                # Only log first few mismatches to avoid spam
                                if len([w for w in validation_result['warnings'] if 'columns, expected' in w]) <= 3:
                                    logger.warning(f"Validation Warning: {warning_msg}")
                    
                    validation_result['record_count'] = record_count
                    logger.info(f"CSV validation completed: {record_count} data records found")
                    
                    # Validate expected content based on requirements
                    expected_headers = [
                        'data.srcip', 'GeoLocation.country_name', 'data.id',
                        'data.protocol', 'data.url', 'data.browser', 'full_log',
                        'agent.ip', 'agent.name', 'rule.id', 'rule.level',
                        'rule.mitre.id', 'rule.description', 'rule.mitre.technique'
                    ]
                    
                    # Check if we have the expected security alert fields
                    missing_expected_headers = []
                    for expected_header in expected_headers:
                        if expected_header not in headers:
                            missing_expected_headers.append(expected_header)
                    
                    if missing_expected_headers:
                        warning_msg = f"Missing expected security alert fields: {', '.join(missing_expected_headers[:3])}{'...' if len(missing_expected_headers) > 3 else ''}"
                        logger.warning(f"Validation Warning: {warning_msg}")
                        validation_result['warnings'].append(warning_msg)
                    else:
                        logger.info("All expected security alert fields are present in CSV")
                    
                    # Mark validation as successful if we got this far without critical errors
                    validation_result['success'] = True
                    
                    # Log summary
                    logger.info(f"CSV Validation Summary:")
                    logger.info(f"  - File: {filename}")
                    logger.info(f"  - Size: {validation_result['file_size']} bytes")
                    logger.info(f"  - Headers: {len(validation_result['headers'])} columns")
                    logger.info(f"  - Records: {validation_result['record_count']} data rows")
                    logger.info(f"  - Errors: {len(validation_result['errors'])}")
                    logger.info(f"  - Warnings: {len(validation_result['warnings'])}")
                    
                    if validation_result['record_count'] == 0:
                        logger.info("  - Note: CSV contains headers but no data records (this may be expected if no alerts were found)")
                    
            except UnicodeDecodeError as e:
                error_msg = f"CSV file encoding error: {e}"
                logger.error(f"Validation Error: {error_msg}")
                logger.error(f"Error details: {str(e)}")
                logger.error("File may be corrupted or saved with incorrect encoding")
                validation_result['errors'].append(error_msg)
                return validation_result
            except csv.Error as e:
                error_msg = f"CSV format error: {e}"
                logger.error(f"Validation Error: {error_msg}")
                logger.error(f"Error details: {str(e)}")
                logger.error("CSV file may be malformed or corrupted")
                validation_result['errors'].append(error_msg)
                return validation_result
            except Exception as e:
                error_msg = f"Unexpected error reading CSV file: {e}"
                logger.error(f"Validation Error: {error_msg}")
                logger.error(f"Error type: {type(e).__name__}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                validation_result['errors'].append(error_msg)
                return validation_result
                
        except Exception as e:
            error_msg = f"Unexpected error during CSV validation: {e}"
            logger.error(f"Validation Error: {error_msg}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            validation_result['errors'].append(error_msg)
            return validation_result
        
        return validation_result

    def send_to_slack(self, filename):
        """Send CSV file to Slack channel with enhanced error handling and logging"""
        logger.info("Starting Slack file upload process")
        
        # Validate Slack configuration before attempting to send
        logger.info("Validating Slack configuration")
        
        if not self.slack_token:
            error_msg = "Slack token not configured - cannot send file to Slack"
            logger.error(f"Slack configuration error: {error_msg}")
            logger.error("Check SLACK_BOT_TOKEN environment variable")
            logger.error("Ensure bot token has files:write scope")
            print(f"Error: {error_msg}")
            return False
            
        if not self.slack_channel:
            error_msg = "Slack channel not configured - cannot send file to Slack"
            logger.error(f"Slack configuration error: {error_msg}")
            logger.error("Check SLACK_CHANNEL environment variable")
            print(f"Error: {error_msg}")
            return False
        
        logger.info(f"Slack configuration validated - token configured, channel: {self.slack_channel}")
        
        # Validate file exists and is readable
        logger.info(f"Validating file for upload: {filename}")
        
        if not os.path.exists(filename):
            error_msg = f"File {filename} not found"
            logger.error(f"File validation error: {error_msg}")
            logger.error(f"Expected file location: {filename}")
            logger.error("Check if CSV generation completed successfully")
            print(error_msg)
            return False
        
        try:
            file_size = os.path.getsize(filename)
            logger.info(f"File validation successful - size: {file_size} bytes")
            
            # Check if file is readable
            if not os.access(filename, os.R_OK):
                error_msg = f"File {filename} is not readable"
                logger.error(f"File permission error: {error_msg}")
                logger.error("Check file permissions and user access rights")
                print(error_msg)
                return False
                
        except OSError as e:
            error_msg = f"Error accessing file {filename}: {e}"
            logger.error(f"File system error: {error_msg}")
            logger.error(f"Error code: {e.errno}")
            print(error_msg)
            return False

        # Prepare Slack upload
        url = "https://slack.com/api/files.upload"
        report_date = datetime.datetime.now().strftime('%Y-%m-%d')
        
        logger.info(f"Preparing Slack upload to: {url}")
        logger.info(f"Upload parameters:")
        logger.info(f"  - Channel: {self.slack_channel}")
        logger.info(f"  - Filename: {os.path.basename(filename)}")
        logger.info(f"  - Report date: {report_date}")

        try:
            with open(filename, 'rb') as file:
                files = {'file': file}
                data = {
                    'token': self.slack_token,
                    'channels': self.slack_channel,
                    'filename': os.path.basename(filename),  # Use just the filename, not full path
                    'title': f"Daily Wazuh Alert Report - {report_date}",
                    'initial_comment': f"📊 Daily security alert report generated from Wazuh\n📅 Report Date: {report_date}\n📁 File: {os.path.basename(filename)}"
                }

                logger.info("Sending file upload request to Slack API")
                logger.debug(f"Request data: channels={data['channels']}, filename={data['filename']}")
                
                response = requests.post(url, files=files, data=data, timeout=60)
                
                logger.info(f"Slack API response status: {response.status_code}")
                response.raise_for_status()

                result = response.json()
                logger.debug(f"Slack API response: {result}")
                
                if result.get('ok'):
                    success_msg = f"File {os.path.basename(filename)} successfully sent to Slack channel {self.slack_channel}"
                    logger.info(f"Slack upload successful: {success_msg}")
                    
                    # Log additional success details
                    if 'file' in result:
                        file_info = result['file']
                        logger.info(f"Uploaded file details:")
                        logger.info(f"  - File ID: {file_info.get('id', 'unknown')}")
                        logger.info(f"  - File size: {file_info.get('size', 'unknown')} bytes")
                        logger.info(f"  - File type: {file_info.get('filetype', 'unknown')}")
                        logger.info(f"  - Upload timestamp: {file_info.get('timestamp', 'unknown')}")
                    
                    print(success_msg)
                    return True
                else:
                    error_msg = result.get('error', 'Unknown error')
                    logger.error(f"Slack API error: {error_msg}")
                    logger.error(f"Full API response: {result}")
                    
                    # Enhanced error handling with specific troubleshooting
                    if error_msg == 'invalid_auth':
                        logger.error("Authentication failed - Invalid Slack bot token")
                        logger.error("Troubleshooting steps:")
                        logger.error("  1. Verify SLACK_BOT_TOKEN environment variable")
                        logger.error("  2. Check if bot token is valid and not expired")
                        logger.error("  3. Ensure bot has files:write OAuth scope")
                        logger.error("  4. Verify bot is installed in the workspace")
                        print("Hint: Check if your Slack bot token is valid and has the necessary permissions")
                        
                    elif error_msg == 'channel_not_found':
                        logger.error(f"Slack channel not found: {self.slack_channel}")
                        logger.error("Troubleshooting steps:")
                        logger.error("  1. Verify channel name is correct (include # for public channels)")
                        logger.error("  2. Check if channel exists in the workspace")
                        logger.error("  3. Ensure bot has access to the channel")
                        logger.error("  4. For private channels, invite the bot to the channel")
                        print(f"Hint: Check if the Slack channel '{self.slack_channel}' exists and the bot has access")
                        
                    elif error_msg == 'not_in_channel':
                        logger.error(f"Bot is not a member of channel: {self.slack_channel}")
                        logger.error("Troubleshooting steps:")
                        logger.error("  1. Invite the bot to the channel")
                        logger.error("  2. Use /invite @botname in the channel")
                        logger.error("  3. For private channels, add bot as a member")
                        print(f"Hint: Add the bot to the Slack channel '{self.slack_channel}'")
                        
                    elif error_msg == 'file_uploads_disabled':
                        logger.error("File uploads are disabled for this workspace")
                        logger.error("Contact workspace administrator to enable file uploads")
                        print("Error: File uploads are disabled in this Slack workspace")
                        
                    elif error_msg == 'over_file_size_limit':
                        logger.error(f"File size exceeds Slack limits: {file_size} bytes")
                        logger.error("Consider compressing the file or splitting large reports")
                        print("Error: File is too large for Slack upload")
                        
                    elif error_msg == 'rate_limited':
                        logger.error("Slack API rate limit exceeded")
                        logger.error("Wait before retrying or reduce API call frequency")
                        print("Error: Slack API rate limit exceeded - try again later")
                        
                    else:
                        logger.error(f"Unhandled Slack API error: {error_msg}")
                        logger.error("Check Slack API documentation for error details")
                        print(f"Error sending file to Slack: {error_msg}")
                    
                    return False

        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error during Slack upload: {e}")
            logger.error(f"Status code: {e.response.status_code}")
            
            if e.response.status_code == 401:
                logger.error("HTTP 401 Unauthorized - Invalid Slack token")
                logger.error("Check SLACK_BOT_TOKEN environment variable")
            elif e.response.status_code == 403:
                logger.error("HTTP 403 Forbidden - Insufficient permissions")
                logger.error("Check bot OAuth scopes and channel permissions")
            elif e.response.status_code == 429:
                logger.error("HTTP 429 Too Many Requests - Rate limited")
                logger.error("Reduce API call frequency or implement retry logic")
            elif e.response.status_code >= 500:
                logger.error("HTTP 5xx Server Error - Slack service issue")
                logger.error("Check Slack status page for service disruptions")
            
            try:
                error_details = e.response.json()
                logger.error(f"Error response details: {error_details}")
            except:
                logger.error(f"Error response text: {e.response.text}")
            
            print(f"Error sending file to Slack: {e}")
            return False
            
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during Slack upload: {e}")
            logger.error("Failed to connect to Slack API")
            logger.error("Check network connectivity and DNS resolution")
            logger.error("Verify firewall settings allow HTTPS to slack.com")
            print(f"Error sending file to Slack: {e}")
            return False
            
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout error during Slack upload: {e}")
            logger.error("Slack API request timed out after 60 seconds")
            logger.error("Check network latency and file size")
            logger.error("Consider increasing timeout for large files")
            print(f"Error sending file to Slack: {e}")
            return False
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error during Slack upload: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error("Check network configuration and proxy settings")
            
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"HTTP Status Code: {e.response.status_code}")
                try:
                    error_details = e.response.json()
                    logger.error(f"Error details: {error_details}")
                except:
                    logger.error(f"Response text: {e.response.text}")
            
            print(f"Error sending file to Slack: {e}")
            return False
            
        except IOError as e:
            logger.error(f"File I/O error during Slack upload: {e}")
            logger.error(f"Error reading file: {filename}")
            logger.error("Check file permissions and disk integrity")
            print(f"Error reading file for Slack upload: {e}")
            return False
            
        except Exception as e:
            logger.error(f"Unexpected error during Slack upload: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            print(f"Unexpected error sending file to Slack: {e}")
            return False

    def cleanup_file(self, filename):
        """Remove the CSV file after sending with enhanced error handling and logging"""
        logger.info(f"Starting file cleanup process for: {filename}")
        
        try:
            # Check if file exists before attempting removal
            if not os.path.exists(filename):
                logger.warning(f"File cleanup skipped - file does not exist: {filename}")
                logger.warning("File may have been already removed or moved")
                print(f"Warning: File {filename} not found for cleanup")
                return True
            
            # Get file info before removal for logging
            try:
                file_size = os.path.getsize(filename)
                logger.info(f"File to be removed: {filename} ({file_size} bytes)")
            except OSError as e:
                logger.warning(f"Could not get file size before removal: {e}")
            
            # Check if file is writable (can be removed)
            if not os.access(filename, os.W_OK):
                logger.error(f"File cleanup failed - no write permission: {filename}")
                logger.error("Check file permissions and user access rights")
                logger.error("File will remain on disk")
                print(f"Error: Cannot remove file {filename} - permission denied")
                return False
            
            # Remove the file
            logger.info(f"Removing file: {filename}")
            os.remove(filename)
            
            # Verify file was actually removed
            if not os.path.exists(filename):
                logger.info(f"File cleanup successful: {filename}")
                print(f"Cleaned up file: {filename}")
                return True
            else:
                logger.error(f"File cleanup failed - file still exists: {filename}")
                logger.error("File system may have failed to remove the file")
                print(f"Error: File {filename} still exists after removal attempt")
                return False
                
        except PermissionError as e:
            logger.error(f"Permission error during file cleanup: {e}")
            logger.error(f"File: {filename}")
            logger.error(f"Error details: {str(e)}")
            logger.error("Troubleshooting suggestions:")
            logger.error("  - Check file permissions")
            logger.error("  - Ensure file is not in use by another process")
            logger.error("  - Run with appropriate permissions if needed")
            logger.error("File will remain on disk")
            print(f"Error cleaning up file {filename}: {e}")
            return False
            
        except OSError as e:
            logger.error(f"OS error during file cleanup: {e}")
            logger.error(f"File: {filename}")
            logger.error(f"Error code: {e.errno}")
            logger.error(f"Error details: {str(e)}")
            
            if e.errno == 2:  # No such file or directory
                logger.warning("File was already removed or moved")
                print(f"Warning: File {filename} was already removed")
                return True
            elif e.errno == 13:  # Permission denied
                logger.error("Permission denied - check file permissions")
            elif e.errno == 16:  # Device or resource busy
                logger.error("File is in use by another process")
                logger.error("Wait for other processes to release the file")
            elif e.errno == 30:  # Read-only file system
                logger.error("File system is read-only")
                logger.error("Cannot remove files from read-only file system")
            else:
                logger.error(f"System error occurred (errno: {e.errno})")
                logger.error("Check system logs for more details")
            
            logger.error("File will remain on disk")
            print(f"Error cleaning up file {filename}: {e}")
            return False
            
        except Exception as e:
            logger.error(f"Unexpected error during file cleanup: {e}")
            logger.error(f"File: {filename}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            logger.error("File will remain on disk")
            print(f"Unexpected error cleaning up file {filename}: {e}")
            return False

    def run_daily_report(self):
        """Main method to run the daily report generation and sending"""
        execution_start_time = datetime.datetime.now()
        
        # Enhanced logging for major process steps
        logger.info("=" * 60)
        logger.info("STARTING DAILY WAZUH REPORT AUTOMATION")
        logger.info("=" * 60)
        
        # Test mode indicators in logging output
        if self.test_mode:
            logger.info("🧪 [TEST MODE] Starting daily Wazuh report generation")
            logger.info("🧪 [TEST MODE] Slack integration will be skipped")
            print(f"🧪 [TEST MODE] Starting daily Wazuh report generation at {execution_start_time}")
            print("🧪 [TEST MODE] Slack integration will be skipped")
        else:
            logger.info("Starting daily Wazuh report generation in production mode")
            print(f"Starting daily Wazuh report generation at {execution_start_time}")

        logger.info(f"Execution started at: {execution_start_time}")
        logger.info(f"Configuration summary:")
        logger.info(f"  - Test mode: {self.test_mode}")
        logger.info(f"  - Slack enabled: {self.enable_slack}")
        logger.info(f"  - Output directory: {self.output_directory}")
        logger.info(f"  - Wazuh API: {self.wazuh_api_url}")
        logger.info(f"  - OpenSearch: {self.opensearch_url}")

        # Step 1: Generate CSV report
        logger.info("-" * 40)
        logger.info("STEP 1: CSV REPORT GENERATION")
        logger.info("-" * 40)
        
        try:
            logger.info("Initiating CSV report generation process")
            filename = self.generate_csv_report()
            
            if not filename:
                error_msg = "CSV report generation failed - no file was created"
                logger.error(f"STEP 1 FAILED: {error_msg}")
                logger.error("Possible causes:")
                logger.error("  - OpenSearch connection failure")
                logger.error("  - Authentication issues")
                logger.error("  - File system errors")
                logger.error("  - Query execution problems")
                
                if self.test_mode:
                    print("🧪 [TEST MODE] Failed to generate CSV report")
                else:
                    print("Failed to generate CSV report")
                return False
            
            logger.info(f"STEP 1 COMPLETED: CSV report generated successfully")
            logger.info(f"Generated file: {filename}")
            
        except Exception as e:
            error_msg = f"Unexpected error during CSV generation: {e}"
            logger.error(f"STEP 1 FAILED: {error_msg}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            
            if self.test_mode:
                print(f"🧪 [TEST MODE] CSV generation failed with error: {e}")
            else:
                print(f"CSV generation failed with error: {e}")
            return False

        # Step 2: Validate CSV content
        logger.info("-" * 40)
        logger.info("STEP 2: CSV VALIDATION")
        logger.info("-" * 40)
        
        try:
            logger.info("Starting CSV file validation process")
            
            if self.test_mode:
                print("🧪 [TEST MODE] Validating generated CSV file...")
            else:
                print("Validating generated CSV file...")
                
            validation_result = self.validate_csv_content(filename)
            
            if not validation_result['success']:
                error_msg = f"CSV validation failed: {', '.join(validation_result['errors'])}"
                logger.error(f"STEP 2 FAILED: {error_msg}")
                logger.error("Validation errors:")
                for error in validation_result['errors']:
                    logger.error(f"  - {error}")
                
                if validation_result['warnings']:
                    logger.warning("Validation warnings:")
                    for warning in validation_result['warnings']:
                        logger.warning(f"  - {warning}")
                
                if self.test_mode:
                    print(f"🧪 [TEST MODE] {error_msg}")
                else:
                    print(error_msg)
                return False
            else:
                success_msg = f"CSV validation successful: {validation_result['record_count']} records, {validation_result['file_size']} bytes"
                logger.info(f"STEP 2 COMPLETED: {success_msg}")
                
                if validation_result['warnings']:
                    logger.warning("Validation completed with warnings:")
                    for warning in validation_result['warnings']:
                        logger.warning(f"  - {warning}")
                
                if self.test_mode:
                    print(f"🧪 [TEST MODE] {success_msg}")
                else:
                    print(success_msg)
                    
        except Exception as e:
            error_msg = f"Unexpected error during CSV validation: {e}"
            logger.error(f"STEP 2 FAILED: {error_msg}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            
            if self.test_mode:
                print(f"🧪 [TEST MODE] CSV validation failed with error: {e}")
            else:
                print(f"CSV validation failed with error: {e}")
            return False

        # Step 3: Handle Slack integration
        logger.info("-" * 40)
        logger.info("STEP 3: SLACK INTEGRATION")
        logger.info("-" * 40)
        
        try:
            # Handle Slack integration based on configuration
            if not self.enable_slack:
                logger.info("Slack integration disabled by configuration (enable_slack=False)")
                logger.info("STEP 3 SKIPPED: Slack integration disabled")
                
                if self.test_mode:
                    print("🧪 [TEST MODE] Slack integration disabled - test mode with enable_slack=False")
                else:
                    print("Slack integration disabled - enable_slack=False")
                print(f"CSV report saved to: {filename}")
                
                # Log final success
                execution_time = datetime.datetime.now() - execution_start_time
                logger.info("=" * 60)
                logger.info("DAILY REPORT AUTOMATION COMPLETED SUCCESSFULLY")
                logger.info(f"Total execution time: {execution_time}")
                logger.info(f"Final output file: {filename}")
                logger.info("=" * 60)
                
                print("Daily report generation completed successfully")
                return True
                
            elif self.test_mode:
                logger.info("Test mode enabled - skipping Slack integration")
                logger.info("STEP 3 SKIPPED: Test mode active")
                
                print("🧪 [TEST MODE] Skipping Slack integration - test mode enabled")
                print(f"🧪 [TEST MODE] CSV report saved to: {filename}")
                
                # Log final success
                execution_time = datetime.datetime.now() - execution_start_time
                logger.info("=" * 60)
                logger.info("🧪 [TEST MODE] DAILY REPORT AUTOMATION COMPLETED SUCCESSFULLY")
                logger.info(f"Total execution time: {execution_time}")
                logger.info(f"Final output file: {filename}")
                logger.info("=" * 60)
                
                print("🧪 [TEST MODE] Daily report generation completed successfully")
                return True
            
            # Send to Slack (only when enable_slack=True and not in test mode)
            logger.info("Initiating Slack file upload process")
            logger.info(f"Target Slack channel: {self.slack_channel}")
            logger.info(f"File to upload: {filename}")
            
            if self.send_to_slack(filename):
                logger.info("STEP 3 COMPLETED: Report successfully sent to Slack")
                print("Report successfully sent to Slack")
                
                # Clean up file after successful Slack upload
                logger.info("Initiating file cleanup after successful Slack upload")
                self.cleanup_file(filename)
                
                # Log final success
                execution_time = datetime.datetime.now() - execution_start_time
                logger.info("=" * 60)
                logger.info("DAILY REPORT AUTOMATION COMPLETED SUCCESSFULLY")
                logger.info(f"Total execution time: {execution_time}")
                logger.info("File uploaded to Slack and cleaned up")
                logger.info("=" * 60)
                
                return True
            else:
                logger.error("STEP 3 FAILED: Failed to send report to Slack")
                logger.error("Slack upload process encountered errors")
                logger.error(f"File remains available at: {filename}")
                print("Failed to send report to Slack")
                return False
                
        except Exception as e:
            error_msg = f"Unexpected error during Slack integration: {e}"
            logger.error(f"STEP 3 FAILED: {error_msg}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            logger.error(f"File remains available at: {filename}")
            
            print(f"Slack integration failed with error: {e}")
            return False

# Configuration template with environment variable mapping
config_template = {
    # Core Wazuh/OpenSearch parameters (always required)
    'wazuh_api_url': 'https://localhost:55000',          # WAZUH_API_URL
    'wazuh_username': 'wazuh',                           # WAZUH_USERNAME  
    'wazuh_password': 'your_wazuh_password',             # WAZUH_PASSWORD (required)
    'opensearch_url': 'https://localhost:9200',          # OPENSEARCH_URL
    'opensearch_username': 'admin',                      # OPENSEARCH_USERNAME
    'opensearch_password': 'your_opensearch_password',   # OPENSEARCH_PASSWORD (required)
    
    # Slack parameters (conditionally required)
    'slack_token': 'xoxb-your-slack-bot-token',          # SLACK_BOT_TOKEN (required unless test_mode=True and enable_slack=False)
    'slack_channel': '#security-alerts',                 # SLACK_CHANNEL
    
    # Report configuration
    'saved_search_id': 'your_saved_search_id',           # SAVED_SEARCH_ID
    'report_title': 'wazuh_daily_alerts',                # REPORT_TITLE
    
    # New configuration options
    'output_directory': '/opt/wazuh-docker/single-node/auto/reports',  # OUTPUT_DIRECTORY (required)
    'test_mode': False,                                  # TEST_MODE (true/false)
    'enable_slack': True                                 # ENABLE_SLACK (true/false)
}

def interactive_configuration_collector():
    """
    Comprehensive Interactive Configuration Collection System
    
    This function provides an extensive, user-friendly interactive interface for collecting
    all necessary configuration parameters with detailed validation, extensive logging,
    comprehensive error handling, and enhanced user experience features.
    
    Returns:
        dict: Fully validated configuration dictionary with all required parameters
    """
    logger.info("=" * 80)
    logger.info("INITIATING INTERACTIVE CONFIGURATION COLLECTION SYSTEM")
    logger.info("=" * 80)
    logger.info("Starting comprehensive interactive configuration collection process")
    logger.info("Enhanced user experience mode: ACTIVATED")
    logger.info("Extensive validation and error handling: ENABLED")
    logger.info("Detailed logging and progress tracking: ACTIVE")
    
    print("\n" + "=" * 80)
    print("🚀 WAZUH AUTOMATION INTERACTIVE CONFIGURATION SYSTEM")
    print("=" * 80)
    print("Welcome to the comprehensive Wazuh automation configuration wizard!")
    print("This system will guide you through all necessary configuration steps.")
    print("Enhanced features: Input validation, secure password handling, smart defaults")
    print("=" * 80)
    
    config = {}
    configuration_start_time = datetime.datetime.now()
    
    try:
        # Phase 1: Operation Mode Selection with Enhanced Options
        logger.info("PHASE 1: OPERATION MODE SELECTION")
        logger.info("Presenting user with comprehensive operation mode options")
        
        print("\n📋 PHASE 1: OPERATION MODE SELECTION")
        print("-" * 50)
        print("Please select your desired operation mode:")
        print("  [1] CSV Generation Only (No Slack integration)")
        print("  [2] CSV + Slack Integration (Full automation)")
        print("  [3] Test Mode - CSV Only (Enhanced logging)")
        print("  [4] Test Mode - CSV + Slack (Full test suite)")
        print("-" * 50)
        
        while True:
            try:
                logger.debug("Prompting user for operation mode selection")
                mode_choice = input("Enter your choice (1-4): ").strip()
                logger.debug(f"User input received for mode selection: '{mode_choice}'")
                
                if mode_choice == '1':
                    config['test_mode'] = False
                    config['enable_slack'] = False
                    mode_description = "Production CSV Generation Only"
                    logger.info(f"Operation mode selected: {mode_description}")
                    print(f"✅ Selected: {mode_description}")
                    break
                elif mode_choice == '2':
                    config['test_mode'] = False
                    config['enable_slack'] = True
                    mode_description = "Production CSV + Slack Integration"
                    logger.info(f"Operation mode selected: {mode_description}")
                    print(f"✅ Selected: {mode_description}")
                    break
                elif mode_choice == '3':
                    config['test_mode'] = True
                    config['enable_slack'] = False
                    mode_description = "Test Mode - CSV Only"
                    logger.info(f"Operation mode selected: {mode_description}")
                    print(f"✅ Selected: {mode_description}")
                    break
                elif mode_choice == '4':
                    config['test_mode'] = True
                    config['enable_slack'] = True
                    mode_description = "Test Mode - CSV + Slack"
                    logger.info(f"Operation mode selected: {mode_description}")
                    print(f"✅ Selected: {mode_description}")
                    break
                else:
                    logger.warning(f"Invalid mode selection received: '{mode_choice}'")
                    print(f"❌ Invalid choice '{mode_choice}'. Please enter 1, 2, 3, or 4.")
                    continue
                    
            except KeyboardInterrupt:
                logger.info("User interrupted configuration process during mode selection")
                print("\n\n⚠️  Configuration interrupted by user")
                print("Exiting configuration wizard...")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Unexpected error during mode selection: {e}")
                print(f"❌ Error during mode selection: {e}")
                print("Please try again...")
                continue
        
        # Phase 2: Core System Configuration
        logger.info("PHASE 2: CORE SYSTEM CONFIGURATION")
        logger.info("Collecting essential Wazuh and OpenSearch connection parameters")
        
        print(f"\n📡 PHASE 2: CORE SYSTEM CONFIGURATION")
        print("-" * 50)
        print("Configuring essential system connections...")
        
        # Wazuh API Configuration with Enhanced Validation
        logger.debug("Starting Wazuh API configuration collection")
        print("\n🔧 Wazuh API Configuration:")
        
        # Wazuh API URL with smart defaults and validation
        logger.debug("Collecting Wazuh API URL with default value handling")
        default_wazuh_url = "https://localhost:55000"
        wazuh_url_prompt = f"Wazuh API URL (default: {default_wazuh_url}): "
        
        while True:
            try:
                wazuh_url = input(wazuh_url_prompt).strip()
                logger.debug(f"Wazuh URL input received: '{wazuh_url}'")
                
                if not wazuh_url:
                    wazuh_url = default_wazuh_url
                    logger.info(f"Using default Wazuh URL: {wazuh_url}")
                    print(f"  ✅ Using default: {wazuh_url}")
                
                # Enhanced URL validation with detailed error reporting
                if not wazuh_url.startswith(('http://', 'https://')):
                    logger.warning(f"Invalid Wazuh URL format: {wazuh_url}")
                    print("  ❌ URL must start with http:// or https://")
                    print("  💡 Example: https://localhost:55000")
                    continue
                
                config['wazuh_api_url'] = wazuh_url
                logger.info(f"Wazuh API URL configured: {wazuh_url}")
                print(f"  ✅ Wazuh API URL: {wazuh_url}")
                break
                
            except KeyboardInterrupt:
                logger.info("User interrupted during Wazuh URL configuration")
                print("\n\n⚠️  Configuration interrupted")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Error during Wazuh URL configuration: {e}")
                print(f"  ❌ Error: {e}")
                continue
        
        # Wazuh Username with default and validation
        logger.debug("Collecting Wazuh username with default value")
        default_wazuh_username = "wazuh"
        wazuh_username_prompt = f"Wazuh Username (default: {default_wazuh_username}): "
        
        wazuh_username = input(wazuh_username_prompt).strip()
        if not wazuh_username:
            wazuh_username = default_wazuh_username
            logger.info(f"Using default Wazuh username: {wazuh_username}")
            print(f"  ✅ Using default: {wazuh_username}")
        
        config['wazuh_username'] = wazuh_username
        logger.info(f"Wazuh username configured: {wazuh_username}")
        print(f"  ✅ Wazuh Username: {wazuh_username}")
        
        # Wazuh Password with secure input and validation
        logger.debug("Collecting Wazuh password with secure input handling")
        while True:
            try:
                wazuh_password = getpass.getpass("Wazuh Password: ").strip()
                logger.debug("Wazuh password input received (length logged for validation)")
                logger.debug(f"Password length: {len(wazuh_password)} characters")
                
                if not wazuh_password:
                    logger.warning("Empty Wazuh password provided")
                    print("  ❌ Password cannot be empty")
                    print("  💡 Please enter your Wazuh API password")
                    continue
                
                if len(wazuh_password) < 3:
                    logger.warning(f"Wazuh password too short: {len(wazuh_password)} characters")
                    print("  ❌ Password seems too short (minimum 3 characters)")
                    print("  💡 Please verify your password")
                    continue
                
                config['wazuh_password'] = wazuh_password
                logger.info("Wazuh password configured successfully")
                print("  ✅ Wazuh Password: ***CONFIGURED***")
                break
                
            except KeyboardInterrupt:
                logger.info("User interrupted during Wazuh password configuration")
                print("\n\n⚠️  Configuration interrupted")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Error during Wazuh password configuration: {e}")
                print(f"  ❌ Error: {e}")
                continue
        
        # OpenSearch Configuration with Enhanced Validation
        logger.debug("Starting OpenSearch configuration collection")
        print("\n🔍 OpenSearch Configuration:")
        
        # OpenSearch URL with smart defaults
        default_opensearch_url = "https://localhost:9200"
        opensearch_url_prompt = f"OpenSearch URL (default: {default_opensearch_url}): "
        
        while True:
            try:
                opensearch_url = input(opensearch_url_prompt).strip()
                logger.debug(f"OpenSearch URL input received: '{opensearch_url}'")
                
                if not opensearch_url:
                    opensearch_url = default_opensearch_url
                    logger.info(f"Using default OpenSearch URL: {opensearch_url}")
                    print(f"  ✅ Using default: {opensearch_url}")
                
                # Enhanced URL validation
                if not opensearch_url.startswith(('http://', 'https://')):
                    logger.warning(f"Invalid OpenSearch URL format: {opensearch_url}")
                    print("  ❌ URL must start with http:// or https://")
                    print("  💡 Example: https://localhost:9200")
                    continue
                
                config['opensearch_url'] = opensearch_url
                logger.info(f"OpenSearch URL configured: {opensearch_url}")
                print(f"  ✅ OpenSearch URL: {opensearch_url}")
                break
                
            except KeyboardInterrupt:
                logger.info("User interrupted during OpenSearch URL configuration")
                print("\n\n⚠️  Configuration interrupted")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Error during OpenSearch URL configuration: {e}")
                print(f"  ❌ Error: {e}")
                continue
        
        # OpenSearch Username with default
        default_opensearch_username = "admin"
        opensearch_username_prompt = f"OpenSearch Username (default: {default_opensearch_username}): "
        
        opensearch_username = input(opensearch_username_prompt).strip()
        if not opensearch_username:
            opensearch_username = default_opensearch_username
            logger.info(f"Using default OpenSearch username: {opensearch_username}")
            print(f"  ✅ Using default: {opensearch_username}")
        
        config['opensearch_username'] = opensearch_username
        logger.info(f"OpenSearch username configured: {opensearch_username}")
        print(f"  ✅ OpenSearch Username: {opensearch_username}")
        
        # OpenSearch Password with secure input
        while True:
            try:
                opensearch_password = getpass.getpass("OpenSearch Password: ").strip()
                logger.debug("OpenSearch password input received")
                logger.debug(f"Password length: {len(opensearch_password)} characters")
                
                if not opensearch_password:
                    logger.warning("Empty OpenSearch password provided")
                    print("  ❌ Password cannot be empty")
                    continue
                
                if len(opensearch_password) < 3:
                    logger.warning(f"OpenSearch password too short: {len(opensearch_password)} characters")
                    print("  ❌ Password seems too short (minimum 3 characters)")
                    continue
                
                config['opensearch_password'] = opensearch_password
                logger.info("OpenSearch password configured successfully")
                print("  ✅ OpenSearch Password: ***CONFIGURED***")
                break
                
            except KeyboardInterrupt:
                logger.info("User interrupted during OpenSearch password configuration")
                print("\n\n⚠️  Configuration interrupted")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Error during OpenSearch password configuration: {e}")
                print(f"  ❌ Error: {e}")
                continue
        
        # Phase 3: Slack Configuration (Conditional)
        if config['enable_slack']:
            logger.info("PHASE 3: SLACK INTEGRATION CONFIGURATION")
            logger.info("Collecting Slack integration parameters")
            
            print(f"\n💬 PHASE 3: SLACK INTEGRATION CONFIGURATION")
            print("-" * 50)
            print("Configuring Slack integration parameters...")
            
            # Slack Bot Token with enhanced validation
            while True:
                try:
                    slack_token = getpass.getpass("Slack Bot Token (xoxb-...): ").strip()
                    logger.debug("Slack token input received")
                    logger.debug(f"Token length: {len(slack_token)} characters")
                    
                    if not slack_token:
                        logger.warning("Empty Slack token provided")
                        print("  ❌ Slack token cannot be empty")
                        print("  💡 Format: xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx")
                        continue
                    
                    if not slack_token.startswith('xoxb-'):
                        logger.warning(f"Invalid Slack token format: {slack_token[:10]}...")
                        print("  ❌ Slack bot token must start with 'xoxb-'")
                        print("  💡 Get your token from: https://api.slack.com/apps")
                        continue
                    
                    if len(slack_token) < 50:
                        logger.warning(f"Slack token seems too short: {len(slack_token)} characters")
                        print("  ❌ Slack token seems too short")
                        print("  💡 Valid tokens are typically 50+ characters")
                        continue
                    
                    config['slack_token'] = slack_token
                    logger.info("Slack token configured successfully")
                    print("  ✅ Slack Token: ***CONFIGURED***")
                    break
                    
                except KeyboardInterrupt:
                    logger.info("User interrupted during Slack token configuration")
                    print("\n\n⚠️  Configuration interrupted")
                    sys.exit(0)
                except Exception as e:
                    logger.error(f"Error during Slack token configuration: {e}")
                    print(f"  ❌ Error: {e}")
                    continue
            
            # Slack Channel with validation
            default_slack_channel = "#security-alerts"
            slack_channel_prompt = f"Slack Channel (default: {default_slack_channel}): "
            
            while True:
                try:
                    slack_channel = input(slack_channel_prompt).strip()
                    logger.debug(f"Slack channel input received: '{slack_channel}'")
                    
                    if not slack_channel:
                        slack_channel = default_slack_channel
                        logger.info(f"Using default Slack channel: {slack_channel}")
                        print(f"  ✅ Using default: {slack_channel}")
                    
                    if not slack_channel.startswith('#'):
                        logger.warning(f"Invalid Slack channel format: {slack_channel}")
                        print("  ❌ Slack channel must start with '#'")
                        print("  💡 Example: #security-alerts")
                        continue
                    
                    config['slack_channel'] = slack_channel
                    logger.info(f"Slack channel configured: {slack_channel}")
                    print(f"  ✅ Slack Channel: {slack_channel}")
                    break
                    
                except KeyboardInterrupt:
                    logger.info("User interrupted during Slack channel configuration")
                    print("\n\n⚠️  Configuration interrupted")
                    sys.exit(0)
                except Exception as e:
                    logger.error(f"Error during Slack channel configuration: {e}")
                    print(f"  ❌ Error: {e}")
                    continue
        else:
            logger.info("PHASE 3: SLACK INTEGRATION SKIPPED")
            logger.info("Slack integration disabled - skipping Slack configuration")
            print(f"\n💬 PHASE 3: SLACK INTEGRATION")
            print("-" * 50)
            print("⏭️  Skipped - Slack integration disabled")
            
            # Set default values for disabled Slack
            config['slack_token'] = None
            config['slack_channel'] = '#security-alerts'
        
        # Phase 4: Report Timeframe Selection with Comprehensive Options
        logger.info("PHASE 4: REPORT TIMEFRAME CONFIGURATION")
        logger.info("Presenting comprehensive timeframe selection with advanced options")
        
        print(f"\n⏰ PHASE 4: REPORT TIMEFRAME SELECTION")
        print("-" * 50)
        print("Select your desired report timeframe with precision control:")
        print("  [1] Last 1 Hour    - Recent activity analysis")
        print("  [2] Last 6 Hours   - Extended recent monitoring")
        print("  [3] Last 12 Hours  - Half-day comprehensive view")
        print("  [4] Last 24 Hours  - Full day analysis (DEFAULT)")
        print("  [5] Last 3 Days    - Extended trend analysis")
        print("  [6] Last 7 Days    - Weekly security overview")
        print("  [7] Last 30 Days   - Monthly comprehensive report")
        print("  [8] Custom Range   - Specify exact start/end times")
        print("-" * 50)
        
        timeframe_options = {
            '1': {'hours': 1, 'description': 'Last 1 Hour', 'log_level': 'RECENT'},
            '2': {'hours': 6, 'description': 'Last 6 Hours', 'log_level': 'EXTENDED_RECENT'},
            '3': {'hours': 12, 'description': 'Last 12 Hours', 'log_level': 'HALF_DAY'},
            '4': {'hours': 24, 'description': 'Last 24 Hours', 'log_level': 'FULL_DAY'},
            '5': {'hours': 72, 'description': 'Last 3 Days', 'log_level': 'EXTENDED_TREND'},
            '6': {'hours': 168, 'description': 'Last 7 Days', 'log_level': 'WEEKLY'},
            '7': {'hours': 720, 'description': 'Last 30 Days', 'log_level': 'MONTHLY'},
            '8': {'custom': True, 'description': 'Custom Range', 'log_level': 'CUSTOM'}
        }
        
        while True:
            try:
                logger.debug("Prompting user for comprehensive timeframe selection")
                timeframe_choice = input("Enter your timeframe choice (1-8, default: 4): ").strip()
                logger.debug(f"Timeframe selection input received: '{timeframe_choice}'")
                
                if not timeframe_choice:
                    timeframe_choice = '4'  # Default to 24 hours
                    logger.info("Using default timeframe: Last 24 Hours")
                    print("  ✅ Using default: Last 24 Hours")
                
                if timeframe_choice not in timeframe_options:
                    logger.warning(f"Invalid timeframe selection: '{timeframe_choice}'")
                    print(f"  ❌ Invalid choice '{timeframe_choice}'. Please enter 1-8.")
                    continue
                
                selected_option = timeframe_options[timeframe_choice]
                logger.info(f"Timeframe selected: {selected_option['description']}")
                logger.info(f"Timeframe log level: {selected_option['log_level']}")
                
                if selected_option.get('custom'):
                    # Custom timeframe configuration with extensive validation
                    logger.info("CUSTOM TIMEFRAME CONFIGURATION INITIATED")
                    logger.info("Collecting custom start and end times with validation")
                    
                    print(f"\n📅 CUSTOM TIMEFRAME CONFIGURATION")
                    print("-" * 40)
                    print("Configure your custom time range:")
                    print("Format examples:")
                    print("  • 2024-01-15 14:30:00 (YYYY-MM-DD HH:MM:SS)")
                    print("  • 2024-01-15 (defaults to 00:00:00)")
                    print("  • Leave empty for relative times")
                    print()
                    
                    # Custom start time with comprehensive validation
                    while True:
                        try:
                            start_input = input("Start time (or 'back' to return): ").strip()
                            logger.debug(f"Custom start time input: '{start_input}'")
                            
                            if start_input.lower() == 'back':
                                logger.info("User requested return to timeframe selection")
                                print("  ↩️  Returning to timeframe selection...")
                                break
                            
                            if not start_input:
                                # Default to 24 hours ago
                                start_time = datetime.datetime.now() - datetime.timedelta(hours=24)
                                logger.info(f"Using default start time: {start_time}")
                                print(f"  ✅ Default start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
                            else:
                                # Parse custom start time with multiple format support
                                try:
                                    if len(start_input) == 10:  # YYYY-MM-DD format
                                        start_time = datetime.datetime.strptime(start_input, '%Y-%m-%d')
                                    elif len(start_input) == 19:  # YYYY-MM-DD HH:MM:SS format
                                        start_time = datetime.datetime.strptime(start_input, '%Y-%m-%d %H:%M:%S')
                                    else:
                                        raise ValueError("Invalid date format")
                                    
                                    logger.info(f"Custom start time parsed: {start_time}")
                                    print(f"  ✅ Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
                                    
                                except ValueError as e:
                                    logger.warning(f"Invalid start time format: {start_input}")
                                    print(f"  ❌ Invalid format: {start_input}")
                                    print("  💡 Use: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
                                    continue
                            
                            # Custom end time with validation
                            while True:
                                try:
                                    end_input = input("End time (default: now): ").strip()
                                    logger.debug(f"Custom end time input: '{end_input}'")
                                    
                                    if not end_input:
                                        end_time = datetime.datetime.now()
                                        logger.info(f"Using current time as end: {end_time}")
                                        print(f"  ✅ End time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
                                    else:
                                        try:
                                            if len(end_input) == 10:
                                                end_time = datetime.datetime.strptime(end_input, '%Y-%m-%d')
                                                end_time = end_time.replace(hour=23, minute=59, second=59)
                                            elif len(end_input) == 19:
                                                end_time = datetime.datetime.strptime(end_input, '%Y-%m-%d %H:%M:%S')
                                            else:
                                                raise ValueError("Invalid date format")
                                            
                                            logger.info(f"Custom end time parsed: {end_time}")
                                            print(f"  ✅ End time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
                                            
                                        except ValueError:
                                            logger.warning(f"Invalid end time format: {end_input}")
                                            print(f"  ❌ Invalid format: {end_input}")
                                            print("  💡 Use: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
                                            continue
                                    
                                    # Validate time range logic
                                    if start_time >= end_time:
                                        logger.warning("Invalid time range: start time >= end time")
                                        print("  ❌ Start time must be before end time")
                                        print(f"  Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
                                        print(f"  End:   {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
                                        continue
                                    
                                    # Calculate and validate duration
                                    duration = end_time - start_time
                                    duration_hours = duration.total_seconds() / 3600
                                    
                                    logger.info(f"Custom timeframe duration: {duration_hours:.2f} hours")
                                    
                                    if duration_hours > 720:  # More than 30 days
                                        logger.warning(f"Very long duration selected: {duration_hours:.2f} hours")
                                        print(f"  ⚠️  Warning: Very long duration ({duration_hours:.1f} hours)")
                                        print("  This may result in large reports and longer processing time")
                                        
                                        confirm = input("  Continue with this duration? (y/N): ").strip().lower()
                                        if confirm not in ['y', 'yes']:
                                            continue
                                    
                                    # Store custom timeframe configuration
                                    config['custom_timeframe'] = True
                                    config['start_time'] = start_time.strftime('%Y-%m-%dT%H:%M:%S')
                                    config['end_time'] = end_time.strftime('%Y-%m-%dT%H:%M:%S')
                                    config['timeframe_hours'] = duration_hours
                                    config['timeframe_description'] = f"Custom: {start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}"
                                    
                                    logger.info("Custom timeframe configuration completed successfully")
                                    print(f"\n  📊 CUSTOM TIMEFRAME SUMMARY:")
                                    print(f"    Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
                                    print(f"    End:   {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
                                    print(f"    Duration: {duration_hours:.1f} hours ({duration.days} days)")
                                    
                                    break
                                    
                                except KeyboardInterrupt:
                                    logger.info("User interrupted custom end time configuration")
                                    print("\n\n⚠️  Configuration interrupted")
                                    sys.exit(0)
                            
                            break
                            
                        except KeyboardInterrupt:
                            logger.info("User interrupted custom start time configuration")
                            print("\n\n⚠️  Configuration interrupted")
                            sys.exit(0)
                    
                    if start_input.lower() == 'back':
                        continue  # Return to main timeframe selection
                    
                else:
                    # Standard timeframe configuration
                    hours = selected_option['hours']
                    description = selected_option['description']
                    
                    # Calculate start and end times for standard timeframes
                    end_time = datetime.datetime.now()
                    start_time = end_time - datetime.timedelta(hours=hours)
                    
                    config['custom_timeframe'] = False
                    config['start_time'] = start_time.strftime('%Y-%m-%dT%H:%M:%S')
                    config['end_time'] = end_time.strftime('%Y-%m-%dT%H:%M:%S')
                    config['timeframe_hours'] = hours
                    config['timeframe_description'] = description
                    
                    logger.info(f"Standard timeframe configured: {description}")
                    logger.info(f"Timeframe duration: {hours} hours")
                    logger.info(f"Start time: {start_time}")
                    logger.info(f"End time: {end_time}")
                    
                    print(f"  ✅ Timeframe: {description}")
                    print(f"  📅 From: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"  📅 To:   {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"  ⏱️  Duration: {hours} hours")
                
                # Timeframe impact analysis and warnings
                logger.debug("Performing timeframe impact analysis")
                
                if config['timeframe_hours'] <= 1:
                    print(f"\n  📈 ANALYSIS: Very recent data - may have limited results")
                    logger.info("Timeframe impact: Very recent - limited data expected")
                elif config['timeframe_hours'] <= 24:
                    print(f"\n  📈 ANALYSIS: Standard daily report timeframe")
                    logger.info("Timeframe impact: Standard daily range")
                elif config['timeframe_hours'] <= 168:
                    print(f"\n  📈 ANALYSIS: Extended analysis - comprehensive data expected")
                    logger.info("Timeframe impact: Extended range - comprehensive data")
                else:
                    print(f"\n  📈 ANALYSIS: Long-term analysis - large dataset expected")
                    print(f"  ⚠️  Note: Processing may take longer for extended timeframes")
                    logger.info("Timeframe impact: Long-term range - large dataset expected")
                
                break
                
            except KeyboardInterrupt:
                logger.info("User interrupted timeframe configuration")
                print("\n\n⚠️  Configuration interrupted")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Error during timeframe configuration: {e}")
                print(f"  ❌ Error: {e}")
                continue
        
        # Phase 5: Advanced Configuration Options
        logger.info("PHASE 5: ADVANCED CONFIGURATION OPTIONS")
        logger.info("Collecting advanced configuration parameters")
        
        print(f"\n⚙️  PHASE 5: ADVANCED CONFIGURATION")
        print("-" * 50)
        print("Configuring advanced options...")
        
        # Output Directory Configuration
        default_output_dir = "/opt/wazuh-docker/single-node/auto/reports"
        output_dir_prompt = f"Output Directory (default: {default_output_dir}): "
        
        while True:
            try:
                output_dir = input(output_dir_prompt).strip()
                logger.debug(f"Output directory input received: '{output_dir}'")
                
                if not output_dir:
                    output_dir = default_output_dir
                    logger.info(f"Using default output directory: {output_dir}")
                    print(f"  ✅ Using default: {output_dir}")
                
                # Basic path validation
                if not os.path.isabs(output_dir):
                    logger.warning(f"Output directory is not absolute path: {output_dir}")
                    print("  ⚠️  Warning: Path is not absolute")
                    print("  💡 Recommended: Use absolute paths like /opt/reports")
                    
                    confirm = input("  Continue anyway? (y/N): ").strip().lower()
                    if confirm not in ['y', 'yes']:
                        continue
                
                config['output_directory'] = output_dir
                logger.info(f"Output directory configured: {output_dir}")
                print(f"  ✅ Output Directory: {output_dir}")
                break
                
            except KeyboardInterrupt:
                logger.info("User interrupted during output directory configuration")
                print("\n\n⚠️  Configuration interrupted")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Error during output directory configuration: {e}")
                print(f"  ❌ Error: {e}")
                continue
        
        # Report Configuration
        default_report_title = "wazuh_daily_alerts"
        report_title_prompt = f"Report Title (default: {default_report_title}): "
        
        report_title = input(report_title_prompt).strip()
        if not report_title:
            report_title = default_report_title
            logger.info(f"Using default report title: {report_title}")
            print(f"  ✅ Using default: {report_title}")
        
        config['report_title'] = report_title
        config['saved_search_id'] = ""  # Set default for saved search
        
        logger.info(f"Report title configured: {report_title}")
        print(f"  ✅ Report Title: {report_title}")
        
        # Configuration Summary and Confirmation
        configuration_duration = datetime.datetime.now() - configuration_start_time
        logger.info("CONFIGURATION COLLECTION COMPLETED")
        logger.info(f"Total configuration time: {configuration_duration}")
        logger.info("Presenting configuration summary to user")
        
        print(f"\n📋 CONFIGURATION SUMMARY")
        print("=" * 50)
        print(f"Operation Mode: {'Test' if config['test_mode'] else 'Production'}")
        print(f"Slack Integration: {'Enabled' if config['enable_slack'] else 'Disabled'}")
        print(f"Wazuh API: {config['wazuh_api_url']}")
        print(f"OpenSearch: {config['opensearch_url']}")
        print(f"Output Directory: {config['output_directory']}")
        print(f"Report Title: {config['report_title']}")
        if config['enable_slack']:
            print(f"Slack Channel: {config['slack_channel']}")
        print("=" * 50)
        print(f"Configuration completed in: {configuration_duration}")
        
        # Final confirmation
        while True:
            try:
                confirm = input("\n✅ Proceed with this configuration? (Y/n): ").strip().lower()
                logger.debug(f"Configuration confirmation input: '{confirm}'")
                
                if confirm in ['', 'y', 'yes']:
                    logger.info("Configuration confirmed by user")
                    print("🚀 Configuration confirmed! Starting automation...")
                    break
                elif confirm in ['n', 'no']:
                    logger.info("Configuration rejected by user")
                    print("❌ Configuration cancelled by user")
                    print("Exiting...")
                    sys.exit(0)
                else:
                    print("Please enter 'y' for yes or 'n' for no")
                    continue
                    
            except KeyboardInterrupt:
                logger.info("User interrupted during final confirmation")
                print("\n\n⚠️  Configuration interrupted")
                sys.exit(0)
            except Exception as e:
                logger.error(f"Error during final confirmation: {e}")
                print(f"❌ Error: {e}")
                continue
        
        logger.info("=" * 80)
        logger.info("INTERACTIVE CONFIGURATION COLLECTION COMPLETED SUCCESSFULLY")
        logger.info("=" * 80)
        logger.info(f"Final configuration contains {len(config)} parameters")
        logger.info("Configuration ready for automation system initialization")
        
        return config
        
    except Exception as e:
        logger.error("=" * 80)
        logger.error("CRITICAL ERROR IN INTERACTIVE CONFIGURATION SYSTEM")
        logger.error("=" * 80)
        logger.error(f"Unexpected error during configuration collection: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        logger.error("Configuration collection failed - system cannot continue")
        
        print("\n" + "=" * 80)
        print("❌ CRITICAL CONFIGURATION ERROR")
        print("=" * 80)
        print(f"An unexpected error occurred: {e}")
        print("Please check the logs for detailed error information")
        print("Configuration collection failed - exiting...")
        
        sys.exit(1)

def load_configuration():
    """
    Load configuration from environment variables with proper handling of new parameters
    and validation logic for test mode
    """
    logger.info("Starting configuration loading from environment variables")
    
    try:
        # Load all configuration parameters from environment variables
        logger.debug("Loading core Wazuh/OpenSearch parameters")
        
        # Core Wazuh/OpenSearch parameters (always required)
        wazuh_api_url = os.getenv('WAZUH_API_URL', 'https://localhost:55000')
        wazuh_username = os.getenv('WAZUH_USERNAME', 'wazuh')
        wazuh_password = os.getenv('WAZUH_PASSWORD')
        opensearch_url = os.getenv('OPENSEARCH_URL', 'https://localhost:9200')
        opensearch_username = os.getenv('OPENSEARCH_USERNAME', 'admin')
        opensearch_password = os.getenv('OPENSEARCH_PASSWORD')
        
        logger.debug("Loading Slack parameters")
        
        # Slack parameters (optional in test mode)
        slack_token = os.getenv('SLACK_BOT_TOKEN')
        slack_channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
        
        logger.debug("Loading report configuration parameters")
        
        # Report configuration
        saved_search_id = os.getenv('SAVED_SEARCH_ID', '')
        report_title = os.getenv('REPORT_TITLE', 'wazuh_daily_alerts')
        
        logger.debug("Loading new configuration options")
        
        # New configuration options with environment variable support
        output_directory = os.getenv('OUTPUT_DIRECTORY', '/opt/wazuh-docker/single-node/auto/reports')
        test_mode = _parse_boolean_env('TEST_MODE', False)
        enable_slack = _parse_boolean_env('ENABLE_SLACK', True)
        
        # Log configuration loading details (without sensitive data)
        logger.info("Configuration parameters loaded:")
        logger.info(f"  - WAZUH_API_URL: {wazuh_api_url}")
        logger.info(f"  - WAZUH_USERNAME: {wazuh_username}")
        logger.info(f"  - WAZUH_PASSWORD: {'***SET***' if wazuh_password else 'NOT SET'}")
        logger.info(f"  - OPENSEARCH_URL: {opensearch_url}")
        logger.info(f"  - OPENSEARCH_USERNAME: {opensearch_username}")
        logger.info(f"  - OPENSEARCH_PASSWORD: {'***SET***' if opensearch_password else 'NOT SET'}")
        logger.info(f"  - SLACK_BOT_TOKEN: {'***SET***' if slack_token else 'NOT SET'}")
        logger.info(f"  - SLACK_CHANNEL: {slack_channel}")
        logger.info(f"  - SAVED_SEARCH_ID: {saved_search_id}")
        logger.info(f"  - REPORT_TITLE: {report_title}")
        logger.info(f"  - OUTPUT_DIRECTORY: {output_directory}")
        logger.info(f"  - TEST_MODE: {test_mode}")
        logger.info(f"  - ENABLE_SLACK: {enable_slack}")
        
        # Validate critical configuration values
        logger.debug("Performing basic configuration validation")
        
        # Validate URLs
        if not wazuh_api_url.startswith(('http://', 'https://')):
            logger.warning(f"WAZUH_API_URL may be invalid (missing protocol): {wazuh_api_url}")
        
        if not opensearch_url.startswith(('http://', 'https://')):
            logger.warning(f"OPENSEARCH_URL may be invalid (missing protocol): {opensearch_url}")
        
        # Validate Slack channel format
        if slack_channel and not slack_channel.startswith('#'):
            logger.warning(f"SLACK_CHANNEL should start with '#': {slack_channel}")
        
        # Validate output directory path
        if not output_directory or not isinstance(output_directory, str):
            logger.error("OUTPUT_DIRECTORY is invalid or empty")
        elif not os.path.isabs(output_directory):
            logger.warning(f"OUTPUT_DIRECTORY is not an absolute path: {output_directory}")
        
        # Build configuration dictionary
        config = {
            'wazuh_api_url': wazuh_api_url,
            'wazuh_username': wazuh_username,
            'wazuh_password': wazuh_password,
            'opensearch_url': opensearch_url,
            'opensearch_username': opensearch_username,
            'opensearch_password': opensearch_password,
            'slack_token': slack_token,
            'slack_channel': slack_channel,
            'saved_search_id': saved_search_id,
            'report_title': report_title,
            'output_directory': output_directory,
            'test_mode': test_mode,
            'enable_slack': enable_slack
        }
        
        logger.info("Configuration loading completed successfully")
        logger.debug(f"Configuration dictionary contains {len(config)} parameters")
        
        return config
        
    except Exception as e:
        logger.error(f"Critical error during configuration loading: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        logger.error("Failed to load configuration from environment variables")
        logger.error("Check environment variable settings and system configuration")
        raise

def _parse_boolean_env(env_var_name, default_value):
    """
    Parse boolean environment variables with proper handling of various string representations
    
    Args:
        env_var_name (str): Name of the environment variable
        default_value (bool): Default value if environment variable is not set
        
    Returns:
        bool: Parsed boolean value
    """
    logger.debug(f"Parsing boolean environment variable: {env_var_name}")
    
    try:
        env_value = os.getenv(env_var_name)
        
        if env_value is None:
            logger.debug(f"{env_var_name} not set, using default value: {default_value}")
            return default_value
        
        logger.debug(f"{env_var_name} raw value: '{env_value}'")
        
        # Handle various string representations of boolean values
        original_value = env_value
        env_value = env_value.lower().strip()
        
        logger.debug(f"{env_var_name} normalized value: '{env_value}'")
        
        # True values
        if env_value in ['true', '1', 'yes', 'on', 'enabled']:
            logger.debug(f"{env_var_name} parsed as True")
            return True
        
        # False values  
        if env_value in ['false', '0', 'no', 'off', 'disabled']:
            logger.debug(f"{env_var_name} parsed as False")
            return False
        
        # Invalid values - log detailed warning and use default
        logger.warning(f"Invalid boolean value for {env_var_name}: '{original_value}'")
        logger.warning(f"Expected values: true/false, 1/0, yes/no, on/off, enabled/disabled")
        logger.warning(f"Using default value: {default_value}")
        logger.warning("Environment variable parsing troubleshooting:")
        logger.warning(f"  - Check {env_var_name} environment variable spelling")
        logger.warning(f"  - Ensure value is one of the supported boolean formats")
        logger.warning(f"  - Remove any extra whitespace or special characters")
        logger.warning(f"  - Current value: '{original_value}' (length: {len(original_value)})")
        
        print(f"Warning: Invalid boolean value '{original_value}' for {env_var_name}, using default: {default_value}")
        return default_value
        
    except Exception as e:
        logger.error(f"Error parsing boolean environment variable {env_var_name}: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Raw environment value: {os.getenv(env_var_name)}")
        logger.error(f"Using default value: {default_value}")
        logger.error("This may indicate a system-level issue with environment variable access")
        
        print(f"Error parsing {env_var_name}: {e}, using default: {default_value}")
        return default_value

def validate_configuration(config):
    """
    Validate configuration with conditional requirements based on test mode and enable_slack settings
    
    Args:
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (is_valid, missing_fields, validation_messages)
    """
    logger.info("Starting comprehensive configuration validation")
    
    validation_messages = []
    missing_fields = []
    warnings = []
    
    try:
        # Always required fields (core functionality)
        always_required = ['wazuh_password', 'opensearch_password']
        
        logger.debug("Validating always required fields")
        
        # Check always required fields
        for field in always_required:
            field_value = config.get(field)
            logger.debug(f"Checking required field '{field}': {'SET' if field_value else 'NOT SET'}")
            
            if not field_value:
                missing_fields.append(field)
                logger.error(f"Required field missing: {field}")
            elif not isinstance(field_value, str):
                missing_fields.append(field)
                logger.error(f"Required field has invalid type: {field} (expected string, got {type(field_value).__name__})")
            elif not field_value.strip():
                missing_fields.append(field)
                logger.error(f"Required field is empty or whitespace only: {field}")
            else:
                logger.debug(f"Required field validation passed: {field}")
        
        # Slack-related fields are conditionally required
        slack_required_fields = ['slack_token']
        
        # Determine if Slack parameters are required
        test_mode = config.get('test_mode', False)
        enable_slack = config.get('enable_slack', True)
        
        logger.info(f"Configuration mode analysis: test_mode={test_mode}, enable_slack={enable_slack}")
        
        if test_mode:
            validation_messages.append("Running in test mode - Slack parameters are optional")
            logger.info("Test mode detected - applying test mode validation rules")
            
            # In test mode, Slack parameters are only required if enable_slack is explicitly True
            if enable_slack:
                validation_messages.append("Test mode with Slack enabled - Slack parameters required")
                logger.info("Test mode with Slack enabled - validating Slack parameters")
                
                for field in slack_required_fields:
                    field_value = config.get(field)
                    logger.debug(f"Checking Slack field '{field}' in test mode: {'SET' if field_value else 'NOT SET'}")
                    
                    if not field_value:
                        missing_fields.append(field)
                        logger.error(f"Slack field missing in test mode with Slack enabled: {field}")
                    elif not isinstance(field_value, str):
                        missing_fields.append(field)
                        logger.error(f"Slack field has invalid type: {field} (expected string, got {type(field_value).__name__})")
                    elif not field_value.strip():
                        missing_fields.append(field)
                        logger.error(f"Slack field is empty or whitespace only: {field}")
                    else:
                        logger.debug(f"Slack field validation passed: {field}")
            else:
                validation_messages.append("Test mode with Slack disabled - Slack parameters not required")
                logger.info("Test mode with Slack disabled - skipping Slack parameter validation")
        else:
            # In production mode, Slack parameters are required unless explicitly disabled
            logger.info("Production mode detected - applying production validation rules")
            
            if enable_slack:
                validation_messages.append("Production mode with Slack enabled - Slack parameters required")
                logger.info("Production mode with Slack enabled - validating Slack parameters")
                
                for field in slack_required_fields:
                    field_value = config.get(field)
                    logger.debug(f"Checking Slack field '{field}' in production mode: {'SET' if field_value else 'NOT SET'}")
                    
                    if not field_value:
                        missing_fields.append(field)
                        logger.error(f"Slack field missing in production mode: {field}")
                    elif not isinstance(field_value, str):
                        missing_fields.append(field)
                        logger.error(f"Slack field has invalid type: {field} (expected string, got {type(field_value).__name__})")
                    elif not field_value.strip():
                        missing_fields.append(field)
                        logger.error(f"Slack field is empty or whitespace only: {field}")
                    else:
                        logger.debug(f"Slack field validation passed: {field}")
            else:
                validation_messages.append("Production mode with Slack disabled - Slack parameters not required")
                logger.info("Production mode with Slack disabled - skipping Slack parameter validation")
        
        # Validate output_directory parameter with enhanced checks
        logger.debug("Validating output_directory parameter")
        
        output_directory = config.get('output_directory')
        if not output_directory:
            missing_fields.append('output_directory')
            validation_messages.append("output_directory is required but not set")
            logger.error("output_directory parameter is missing or None")
        elif not isinstance(output_directory, str):
            missing_fields.append('output_directory')
            validation_messages.append(f"output_directory must be a string, got {type(output_directory).__name__}")
            logger.error(f"output_directory has invalid type: {type(output_directory).__name__}")
        elif not output_directory.strip():
            missing_fields.append('output_directory')
            validation_messages.append("output_directory cannot be empty or whitespace only")
            logger.error("output_directory is empty or contains only whitespace")
        else:
            logger.debug(f"output_directory validation passed: {output_directory}")
            
            # Additional output directory validation
            if not os.path.isabs(output_directory):
                warnings.append(f"output_directory is not an absolute path: {output_directory}")
                logger.warning(f"output_directory is not absolute: {output_directory}")
            
            # Check if parent directory exists (if not root)
            parent_dir = os.path.dirname(output_directory)
            if parent_dir and parent_dir != output_directory:  # Avoid infinite recursion for root paths
                if not os.path.exists(parent_dir):
                    warnings.append(f"Parent directory does not exist: {parent_dir}")
                    logger.warning(f"Parent directory does not exist: {parent_dir}")
                elif not os.access(parent_dir, os.W_OK):
                    warnings.append(f"Parent directory is not writable: {parent_dir}")
                    logger.warning(f"Parent directory is not writable: {parent_dir}")
        
        # Validate URL formats
        logger.debug("Validating URL parameters")
        
        url_fields = ['wazuh_api_url', 'opensearch_url']
        for field in url_fields:
            url_value = config.get(field)
            if url_value:
                logger.debug(f"Validating URL field: {field}")
                
                if not isinstance(url_value, str):
                    warnings.append(f"{field} should be a string, got {type(url_value).__name__}")
                    logger.warning(f"{field} has invalid type: {type(url_value).__name__}")
                elif not url_value.startswith(('http://', 'https://')):
                    warnings.append(f"{field} should start with http:// or https://: {url_value}")
                    logger.warning(f"{field} missing protocol: {url_value}")
                else:
                    logger.debug(f"URL validation passed: {field}")
        
        # Validate Slack channel format
        slack_channel = config.get('slack_channel')
        if slack_channel and enable_slack:
            logger.debug("Validating Slack channel format")
            
            if not isinstance(slack_channel, str):
                warnings.append(f"slack_channel should be a string, got {type(slack_channel).__name__}")
                logger.warning(f"slack_channel has invalid type: {type(slack_channel).__name__}")
            elif not slack_channel.startswith('#'):
                warnings.append(f"slack_channel should start with '#': {slack_channel}")
                logger.warning(f"slack_channel missing '#' prefix: {slack_channel}")
            else:
                logger.debug("Slack channel format validation passed")
        
        # Validate report title
        report_title = config.get('report_title')
        if report_title:
            logger.debug("Validating report title")
            
            if not isinstance(report_title, str):
                warnings.append(f"report_title should be a string, got {type(report_title).__name__}")
                logger.warning(f"report_title has invalid type: {type(report_title).__name__}")
            elif not report_title.strip():
                warnings.append("report_title is empty or whitespace only")
                logger.warning("report_title is empty or whitespace only")
            else:
                logger.debug("Report title validation passed")
        
        # Additional validation messages for configuration state
        validation_messages.append(f"Configuration loaded: test_mode={test_mode}, enable_slack={enable_slack}")
        
        # Log warnings if any
        if warnings:
            logger.warning("Configuration validation completed with warnings:")
            for warning in warnings:
                logger.warning(f"  - {warning}")
                validation_messages.append(f"Warning: {warning}")
        
        # Determine overall validation result
        is_valid = len(missing_fields) == 0
        
        # Log validation summary
        logger.info("Configuration validation summary:")
        logger.info(f"  - Valid: {is_valid}")
        logger.info(f"  - Missing fields: {len(missing_fields)}")
        logger.info(f"  - Warnings: {len(warnings)}")
        logger.info(f"  - Validation messages: {len(validation_messages)}")
        
        if missing_fields:
            logger.error("Missing required fields:")
            for field in missing_fields:
                logger.error(f"  - {field}")
        
        if is_valid:
            logger.info("Configuration validation completed successfully")
        else:
            logger.error("Configuration validation failed due to missing required fields")
        
        return is_valid, missing_fields, validation_messages
        
    except Exception as e:
        logger.error(f"Critical error during configuration validation: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        logger.error("Configuration validation failed due to unexpected error")
        
        # Return failure state with error information
        error_message = f"Configuration validation error: {e}"
        return False, ['configuration_validation_error'], [error_message]

if __name__ == "__main__":
    startup_time = datetime.datetime.now()
    
    # Enhanced logging for main execution
    logger.info("=" * 80)
    logger.info("WAZUH REPORT AUTOMATION STARTUP")
    logger.info("=" * 80)
    logger.info(f"Startup time: {startup_time}")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Script location: {os.path.abspath(__file__)}")
    logger.info(f"Working directory: {os.getcwd()}")
    
    try:
        # Interactive Configuration Collection System
        logger.info("Initiating interactive configuration collection system")
        print("Starting interactive configuration wizard...")
        
        config = interactive_configuration_collector()
        logger.info("Configuration loaded successfully")
        
        # Extract new configuration parameters for enhanced handling
        test_mode = config.get('test_mode', False)
        enable_slack = config.get('enable_slack', True)
        output_directory = config.get('output_directory', '/opt/wazuh-docker/single-node/auto/reports')
        
        # Log configuration summary (without sensitive data)
        logger.info("Configuration summary:")
        logger.info(f"  - Wazuh API URL: {config.get('wazuh_api_url', 'not set')}")
        logger.info(f"  - OpenSearch URL: {config.get('opensearch_url', 'not set')}")
        logger.info(f"  - Output directory: {output_directory}")
        logger.info(f"  - Test mode: {test_mode}")
        logger.info(f"  - Slack enabled: {enable_slack}")
        logger.info(f"  - Slack channel: {config.get('slack_channel', 'not set')}")
        logger.info(f"  - Report title: {config.get('report_title', 'not set')}")
        
        # Enhanced configuration mode logging with detailed new parameter handling
        if test_mode:
            logger.info("RUNNING IN TEST MODE:")
            logger.info("  - Enhanced logging and validation enabled")
            logger.info("  - CSV files will be marked as test data")
            logger.info("  - Slack token validation is conditional")
            print("🧪 Test Mode Enabled - Enhanced testing features active")
            
            if enable_slack:
                logger.info("  - Slack integration is ENABLED in test mode")
                print("  📤 Slack integration: ENABLED (requires SLACK_BOT_TOKEN)")
            else:
                logger.info("  - Slack integration is DISABLED in test mode")
                print("  📤 Slack integration: DISABLED (no token required)")
        else:
            logger.info("RUNNING IN PRODUCTION MODE:")
            logger.info("  - Full automation pipeline active")
            print("🚀 Production Mode - Full automation pipeline active")
            
            if enable_slack:
                logger.info("  - Slack integration is ENABLED")
                print("  📤 Slack integration: ENABLED (requires SLACK_BOT_TOKEN)")
            else:
                logger.info("  - Slack integration is DISABLED")
                print("  📤 Slack integration: DISABLED")
        
        # Log output directory configuration
        logger.info(f"CSV output directory: {output_directory}")
        print(f"📁 CSV output directory: {output_directory}")
        
        # Validate configuration with enhanced test mode logic
        logger.info("Starting configuration validation with test mode support")
        is_valid, missing_fields, validation_messages = validate_configuration(config)
        
        # Log validation messages
        logger.info("Configuration validation messages:")
        for message in validation_messages:
            logger.info(f"  - {message}")
            print(f"Config: {message}")
        
        # Enhanced error handling for missing required fields with test mode context
        if not is_valid:
            error_msg = f"Missing required configuration fields: {', '.join(missing_fields)}"
            logger.error(f"Configuration validation failed: {error_msg}")
            
            # Enhanced error messaging based on configuration mode
            logger.error("Configuration requirements based on mode:")
            logger.error("  ALWAYS REQUIRED:")
            logger.error("    - WAZUH_PASSWORD: Wazuh API authentication")
            logger.error("    - OPENSEARCH_PASSWORD: OpenSearch authentication")
            logger.error("")
            
            if test_mode:
                logger.error("  TEST MODE REQUIREMENTS:")
                if enable_slack:
                    logger.error("    - SLACK_BOT_TOKEN: Required (Slack enabled in test mode)")
                else:
                    logger.error("    - SLACK_BOT_TOKEN: Not required (Slack disabled)")
                logger.error("    - OUTPUT_DIRECTORY: Optional (defaults to standard path)")
            else:
                logger.error("  PRODUCTION MODE REQUIREMENTS:")
                if enable_slack:
                    logger.error("    - SLACK_BOT_TOKEN: Required (Slack enabled)")
                else:
                    logger.error("    - SLACK_BOT_TOKEN: Not required (Slack disabled)")
                logger.error("    - OUTPUT_DIRECTORY: Optional (defaults to standard path)")
            
            logger.error("")
            logger.error("Environment variables for new configuration options:")
            logger.error("  - TEST_MODE: 'true'|'false' - Enable test mode (default: false)")
            logger.error("  - ENABLE_SLACK: 'true'|'false' - Enable Slack integration (default: true)")
            logger.error("  - OUTPUT_DIRECTORY: Custom output directory path")
            logger.error("")
            logger.error("Common configuration examples:")
            logger.error("  1. Basic test mode: TEST_MODE=true ENABLE_SLACK=false")
            logger.error("  2. Test with Slack: TEST_MODE=true ENABLE_SLACK=true + SLACK_BOT_TOKEN")
            logger.error("  3. Production no Slack: ENABLE_SLACK=false")
            logger.error("  4. Full production: ENABLE_SLACK=true + SLACK_BOT_TOKEN")
            
            print(f"\n❌ Error: {error_msg}")
            print("\n📋 Configuration Requirements:")
            print("  ALWAYS REQUIRED:")
            print("    - WAZUH_PASSWORD")
            print("    - OPENSEARCH_PASSWORD")
            print("")
            
            if test_mode:
                print("  TEST MODE:")
                if enable_slack:
                    print("    - SLACK_BOT_TOKEN: Required (Slack enabled)")
                else:
                    print("    - SLACK_BOT_TOKEN: Not required (Slack disabled)")
            else:
                print("  PRODUCTION MODE:")
                if enable_slack:
                    print("    - SLACK_BOT_TOKEN: Required (Slack enabled)")
                else:
                    print("    - SLACK_BOT_TOKEN: Not required (Slack disabled)")
            
            print("\n🔧 Environment Variables:")
            print("  - TEST_MODE=true|false (default: false)")
            print("  - ENABLE_SLACK=true|false (default: true)")
            print("  - OUTPUT_DIRECTORY=<path> (optional)")
            print("\n💡 Quick Examples:")
            print("  Basic test: TEST_MODE=true ENABLE_SLACK=false")
            print("  Test + Slack: TEST_MODE=true ENABLE_SLACK=true + SLACK_BOT_TOKEN")
            print("  Prod no Slack: ENABLE_SLACK=false")
            print("  Full prod: ENABLE_SLACK=true + SLACK_BOT_TOKEN")
            
            logger.error("Exiting due to configuration validation failure")
            exit(1)
        
        logger.info("Configuration validation successful")
        print("✅ Configuration validation successful")
        
        # Initialize and run the automation
        logger.info("Initializing WazuhReportAutomator")
        
        try:
            automator = WazuhReportAutomator(config)
            logger.info("WazuhReportAutomator initialized successfully")
            
            logger.info("Starting daily report automation process")
            success = automator.run_daily_report()
            
            if success:
                execution_time = datetime.datetime.now() - startup_time
                logger.info("=" * 80)
                logger.info("AUTOMATION COMPLETED SUCCESSFULLY")
                logger.info(f"Total execution time: {execution_time}")
                logger.info(f"Configuration mode: {'TEST' if test_mode else 'PRODUCTION'}")
                logger.info(f"Slack integration: {'ENABLED' if enable_slack else 'DISABLED'}")
                logger.info(f"Output directory: {output_directory}")
                logger.info("=" * 80)
                
                print("✅ Daily report automation completed successfully")
                if test_mode:
                    print("🧪 Test mode execution completed - check output directory for results")
                else:
                    print("🚀 Production automation completed")
                exit(0)
            else:
                execution_time = datetime.datetime.now() - startup_time
                logger.error("=" * 80)
                logger.error("AUTOMATION FAILED")
                logger.error(f"Total execution time: {execution_time}")
                logger.error(f"Configuration mode: {'TEST' if test_mode else 'PRODUCTION'}")
                logger.error(f"Slack integration: {'ENABLED' if enable_slack else 'DISABLED'}")
                logger.error(f"Output directory: {output_directory}")
                logger.error("Check logs above for specific error details")
                logger.error("=" * 80)
                
                print("❌ Daily report automation failed")
                if test_mode:
                    print("🧪 Test mode execution failed - check logs for debugging")
                else:
                    print("🚀 Production automation failed - check logs and configuration")
                exit(1)
                
        except ValueError as e:
            logger.error(f"Configuration error during initialization: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Configuration mode: {'TEST' if test_mode else 'PRODUCTION'}")
            logger.error(f"Output directory: {output_directory}")
            logger.error("Check configuration parameters and their values")
            logger.error("Common configuration issues:")
            logger.error("  - Invalid output_directory path")
            logger.error("  - Invalid boolean values for TEST_MODE or ENABLE_SLACK")
            logger.error("  - Missing required authentication credentials")
            print(f"❌ Configuration error: {e}")
            print("💡 Check environment variables and configuration values")
            exit(1)
            
        except ConnectionError as e:
            logger.error(f"Network connection error: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Configuration mode: {'TEST' if test_mode else 'PRODUCTION'}")
            logger.error("Check network connectivity to Wazuh and OpenSearch")
            if test_mode:
                logger.error("Test mode troubleshooting:")
                logger.error("  - Verify Wazuh/OpenSearch services are running")
                logger.error("  - Check if test environment is properly configured")
                logger.error("  - Consider using mock data for isolated testing")
            print(f"❌ Connection error: {e}")
            print("🔗 Check network connectivity to Wazuh and OpenSearch services")
            exit(1)
            
        except PermissionError as e:
            logger.error(f"Permission error: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Output directory: {output_directory}")
            logger.error("Check file system permissions and user access rights")
            logger.error("Permission troubleshooting:")
            logger.error(f"  - Verify write access to: {output_directory}")
            logger.error("  - Check parent directory permissions")
            logger.error("  - Consider running with appropriate user permissions")
            if test_mode:
                logger.error("  - Try using a different test output directory")
            print(f"❌ Permission error: {e}")
            print(f"📁 Check write permissions for: {output_directory}")
            exit(1)
            
        except Exception as e:
            logger.error(f"Unexpected error during automation execution: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Configuration mode: {'TEST' if test_mode else 'PRODUCTION'}")
            logger.error(f"Slack integration: {'ENABLED' if enable_slack else 'DISABLED'}")
            logger.error(f"Output directory: {output_directory}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            logger.error("This is an unhandled error - please report this issue")
            print(f"❌ Unexpected error: {e}")
            print("🐛 This appears to be an unhandled error - please check logs")
            exit(1)
            
    except Exception as e:
        # Catch any errors during startup/configuration loading
        logger.error(f"Critical error during startup: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        logger.error("Failed to initialize automation system")
        logger.error("Startup troubleshooting:")
        logger.error("  - Check environment variable configuration")
        logger.error("  - Verify all required environment variables are set")
        logger.error("  - Check for syntax errors in configuration values")
        logger.error("  - Ensure proper boolean format for TEST_MODE and ENABLE_SLACK")
        print(f"💥 Critical startup error: {e}")
        print("🔧 Check environment variables and configuration")
        print("💡 Common issues:")
        print("  - Missing required environment variables")
        print("  - Invalid boolean values (use 'true'/'false')")
        print("  - Invalid path format for OUTPUT_DIRECTORY")
        exit(1)
