import React, { useState, useEffect } from 'react';
import { 
  Play, 
  Shield, 
  Globe, 
  Search, 
  Database, 
  Activity, 
  Clock, 
  CheckCircle, 
  XCircle, 
  AlertCircle,
  Download,
  RefreshCw,
  Eye,
  Zap,
  Target,
  BarChart3,
  Settings,
  Calendar,
  Server,
  AlertTriangle,
  Minus,
  ChevronRight,
  ChevronDown,
  Filter,
  FileText,
  TrendingUp,
  TrendingDown,
  Users,
  Building,
  Award,
  AlertOctagon,
  CheckCircle2,
  Clock3,
  PieChart,
  ArrowRight,
  Mail,
  Printer,
  Share2
} from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000/api';

const Dashboard = () => {
  const [modules, setModules] = useState([]);
  const [scans, setScans] = useState([]);
  const [selectedModules, setSelectedModules] = useState([]);
  const [target, setTarget] = useState('');
  const [activeScan, setActiveScan] = useState(null);
  const [activeTab, setActiveTab] = useState('scan');
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(false);
  
  // State for enhanced monitor tab
  const [expandedModules, setExpandedModules] = useState(new Set());
  const [filterCategory, setFilterCategory] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  // State for executive reports
  const [selectedReportScan, setSelectedReportScan] = useState(null);

  // Fetch initial data
  useEffect(() => {
    fetchModules();
    fetchScans();
    fetchHealth();
    const interval = setInterval(() => {
      fetchScans();
      if (activeScan) {
        fetchScanDetails(activeScan.scan_id);
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [activeScan]);

  const fetchModules = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/modules`);
      const data = await response.json();
      setModules(data.modules || []);
    } catch (error) {
      console.error('Failed to fetch modules:', error);
    }
  };

  const fetchScans = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/scans`);
      const data = await response.json();
      setScans(data.scans || []);
    } catch (error) {
      console.error('Failed to fetch scans:', error);
    }
  };

  const fetchHealth = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/health`);
      const data = await response.json();
      setHealth(data);
    } catch (error) {
      console.error('Failed to fetch health:', error);
    }
  };

  const fetchScanDetails = async (scanId) => {
    try {
      const response = await fetch(`${API_BASE_URL}/scans/${scanId}`);
      const data = await response.json();
      if (data.scan_id) {
        setActiveScan(data);
      }
    } catch (error) {
      console.error('Failed to fetch scan details:', error);
    }
  };

  const startScan = async () => {
    if (!target || selectedModules.length === 0) {
      alert('Please enter a target and select at least one module');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          modules: selectedModules
        })
      });
      
      const data = await response.json();
      if (data.scan_id) {
        setActiveScan(data);
        setActiveTab('monitor');
        fetchScanDetails(data.scan_id);
      }
    } catch (error) {
      console.error('Failed to start scan:', error);
      alert('Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  const toggleModule = (moduleScript) => {
    setSelectedModules(prev => 
      prev.includes(moduleScript) 
        ? prev.filter(m => m !== moduleScript)
        : [...prev, moduleScript]
    );
  };

  const selectAllModules = () => {
    setSelectedModules(modules.map(m => m.script));
  };

  const clearSelection = () => {
    setSelectedModules([]);
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'running': return <Activity className="w-4 h-4 text-blue-500 animate-pulse" />;
      case 'failed': return <XCircle className="w-4 h-4 text-red-500" />;
      case 'queued': return <Clock className="w-4 h-4 text-yellow-500" />;
      default: return <AlertCircle className="w-4 h-4 text-gray-400" />;
    }
  };

  const getCategoryIcon = (category) => {
    switch (category) {
      case 'Network & Infrastructure': return <Server className="w-4 h-4 text-blue-500" />;
      case 'Security & Threat Intelligence': return <Shield className="w-4 h-4 text-red-500" />;
      case 'Web Application Analysis': return <Globe className="w-4 h-4 text-green-500" />;
      default: return <Database className="w-4 h-4 text-gray-500" />;
    }
  };

  // Enhanced monitor tab functions
  const calculateRiskMetrics = () => {
    if (!activeScan?.module_results) return { totalThreats: 0, avgRiskScore: 0, highRiskModules: 0, completedModules: 0 };
    
    const completedModules = activeScan.module_results.filter(m => m.status === 'completed');
    const totalThreats = completedModules.reduce((sum, m) => sum + (m.threats_detected || 0), 0);
    const avgRiskScore = completedModules.reduce((sum, m) => sum + (m.risk_score || calculateRiskScore(m)), 0) / completedModules.length;
    const highRiskModules = completedModules.filter(m => (m.risk_score || calculateRiskScore(m)) >= 7).length;
    
    return {
      totalThreats,
      avgRiskScore: avgRiskScore || 0,
      highRiskModules,
      completedModules: completedModules.length
    };
  };

  // Calculate risk score if not provided by backend
  const calculateRiskScore = (result) => {
    if (result.risk_score) return result.risk_score;
    
    let score = 0;
    
    // Base score on status
    if (result.status === 'failed') score += 2;
    if (result.error) score += 3;
    
    // Score based on threats detected
    if (result.threats_detected) score += result.threats_detected * 2;
    
    // Score based on keywords in output
    const output = result.output?.toLowerCase() || '';
    if (output.includes('error') || output.includes('failed')) score += 2;
    if (output.includes('warning') || output.includes('alert')) score += 1;
    if (output.includes('vulnerable') || output.includes('threat')) score += 3;
    if (output.includes('malware') || output.includes('phishing')) score += 4;
    
    return Math.min(score, 10);
  };

  const getRiskColor = (score) => {
    if (score >= 8) return 'text-red-400';
    if (score >= 6) return 'text-yellow-400'; 
    if (score >= 4) return 'text-blue-400';
    return 'text-green-400';
  };

  const getRiskBgColor = (score) => {
    if (score >= 8) return 'bg-red-500/20 border-red-500/30';
    if (score >= 6) return 'bg-yellow-500/20 border-yellow-500/30';
    if (score >= 4) return 'bg-blue-500/20 border-blue-500/30';
    return 'bg-green-500/20 border-green-500/30';
  };

  const getThreatLevel = (score) => {
    if (score >= 8) return { level: 'Critical', color: 'text-red-400', icon: AlertTriangle };
    if (score >= 6) return { level: 'High', color: 'text-orange-400', icon: AlertCircle };
    if (score >= 4) return { level: 'Medium', color: 'text-yellow-400', icon: Minus };
    return { level: 'Low', color: 'text-green-400', icon: CheckCircle };
  };

  const toggleModuleExpansion = (moduleIndex) => {
    const newExpanded = new Set(expandedModules);
    if (newExpanded.has(moduleIndex)) {
      newExpanded.delete(moduleIndex);
    } else {
      newExpanded.add(moduleIndex);
    }
    setExpandedModules(newExpanded);
  };

  // Executive Reports Functions
  const generateExecutiveReport = (scan) => {
    const metrics = calculateRiskMetrics();
    const completedScans = scans.filter(s => s.status === 'completed');
    const riskTrend = completedScans.length > 1 ? 'improving' : 'stable'; // Simplified trend
    
    return {
      ...scan,
      metrics,
      riskTrend,
      recommendations: generateRecommendations(scan),
      complianceScore: calculateComplianceScore(scan),
      businessImpact: calculateBusinessImpact(scan)
    };
  };

  const generateRecommendations = (scan) => {
    const recommendations = [];
    
    if (!scan?.module_results) return recommendations;
    
    scan.module_results.forEach(result => {
      const riskScore = result.risk_score || calculateRiskScore(result);
      
      if (riskScore >= 8) {
        recommendations.push({
          priority: 'Critical',
          title: `Address ${result.module_name} vulnerabilities`,
          description: `Critical security issues detected in ${result.module_name}. Immediate action required.`,
          effort: 'High',
          impact: 'High'
        });
      } else if (riskScore >= 6) {
        recommendations.push({
          priority: 'High',
          title: `Review ${result.module_name} findings`,
          description: `Security concerns identified that should be addressed soon.`,
          effort: 'Medium',
          impact: 'Medium'
        });
      }
    });
    
    // Add general recommendations
    if (recommendations.length === 0) {
      recommendations.push({
        priority: 'Low',
        title: 'Maintain current security posture',
        description: 'Continue regular security assessments and monitoring.',
        effort: 'Low',
        impact: 'Medium'
      });
    }
    
    return recommendations.slice(0, 5); // Top 5 recommendations
  };

  const calculateComplianceScore = (scan) => {
    if (!scan?.module_results) return 0;
    
    const totalModules = scan.module_results.length;
    const passedModules = scan.module_results.filter(r => {
      const riskScore = r.risk_score || calculateRiskScore(r);
      return riskScore < 6;
    }).length;
    
    return Math.round((passedModules / totalModules) * 100);
  };

  const calculateBusinessImpact = (scan) => {
    const metrics = calculateRiskMetrics();
    
    if (metrics.avgRiskScore >= 8) {
      return {
        level: 'High',
        description: 'Critical vulnerabilities pose significant business risk',
        color: 'text-red-400',
        bgColor: 'bg-red-500/20 border-red-500/30'
      };
    } else if (metrics.avgRiskScore >= 6) {
      return {
        level: 'Medium',
        description: 'Moderate security risks require attention',
        color: 'text-yellow-400',
        bgColor: 'bg-yellow-500/20 border-yellow-500/30'
      };
    } else {
      return {
        level: 'Low',
        description: 'Good security posture with minimal risks',
        color: 'text-green-400',
        bgColor: 'bg-green-500/20 border-green-500/30'
      };
    }
  };

  const downloadExecutiveReport = (reportData) => {
    const content = `
EXECUTIVE SECURITY ASSESSMENT REPORT
====================================

EXECUTIVE SUMMARY
----------------
Target: ${reportData.target}
Assessment Date: ${new Date(reportData.created_at).toLocaleDateString()}
Overall Risk Score: ${reportData.metrics.avgRiskScore.toFixed(1)}/10
Compliance Score: ${reportData.complianceScore}%
Business Impact: ${reportData.businessImpact.level}

KEY FINDINGS
-----------
• Total Threats Detected: ${reportData.metrics.totalThreats}
• High-Risk Areas: ${reportData.metrics.highRiskModules}
• Modules Assessed: ${reportData.metrics.completedModules}

RECOMMENDATIONS
--------------
${reportData.recommendations.map((rec, idx) => 
  `${idx + 1}. ${rec.title} (Priority: ${rec.priority})\n   ${rec.description}`
).join('\n\n')}

NEXT STEPS
----------
1. Address critical vulnerabilities immediately
2. Implement recommended security controls
3. Schedule follow-up assessment in 90 days
4. Review and update security policies

This report was generated by ARGUS Security Assessment Platform.
`;

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `executive-report-${reportData.target}-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadReport = (scan) => {
    const reportContent = generateReport(scan);
    const blob = new Blob([reportContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `argus-report-${scan.target}-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const generateReport = (scan) => {
    let report = `
ARGUS RECONNAISSANCE REPORT
==========================

Target: ${scan.target}
Scan ID: ${scan.scan_id}
Started: ${new Date(scan.created_at).toLocaleString()}
Completed: ${scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'In Progress'}
Status: ${scan.status.toUpperCase()}

SUMMARY
-------
Total Modules: ${scan.total_modules}
Completed: ${scan.completed_modules}
Success Rate: ${scan.summary?.success_rate?.toFixed(1) || 'N/A'}%

RESULTS
-------
`;

    scan.module_results?.forEach((result, index) => {
      report += `
${index + 1}. ${result.module_name}
   Status: ${result.status.toUpperCase()}
   Execution Time: ${result.execution_time}s
   ${result.error ? `Error: ${result.error}` : ''}
   ${result.output ? `Output:\n${result.output}\n` : ''}
`;
    });

    return report;
  };

  const modulesByCategory = modules.reduce((acc, module) => {
    const category = module.category || 'Other';
    if (!acc[category]) acc[category] = [];
    acc[category].push(module);
    return acc;
  }, {});

  // Calculate metrics for enhanced monitor
  const metrics = calculateRiskMetrics();
  const overallThreat = getThreatLevel(metrics.avgRiskScore);

  // Filter results for enhanced monitor
  const filteredResults = activeScan?.module_results?.filter(result => {
    const matchesCategory = filterCategory === 'all' || result.category === filterCategory;
    const matchesStatus = filterStatus === 'all' || result.status === filterStatus;
    const matchesSearch = searchTerm === '' || 
      result.module_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (result.output || '').toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesCategory && matchesStatus && matchesSearch;
  }) || [];

  // Get completed scans for executive reports
  const completedScans = scans.filter(scan => scan.status === 'completed');

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <div className="bg-black/20 backdrop-blur-sm border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg">
                <Target className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">ARGUS</h1>
                <p className="text-sm text-slate-400">Security Assessment Platform</p>
              </div>
            </div>
            
            {health && (
              <div className="flex items-center space-x-4 text-sm">
                <div className="flex items-center space-x-2">
                  <Activity className="w-4 h-4 text-green-400" />
                  <span className="text-slate-300">Status: Online</span>
                </div>
                <div className="flex items-center space-x-2">
                  <BarChart3 className="w-4 h-4 text-blue-400" />
                  <span className="text-slate-300">{health.active_scans} Active</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Database className="w-4 h-4 text-purple-400" />
                  <span className="text-slate-300">{health.module_files_found} Modules</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="max-w-7xl mx-auto px-6 py-4">
        <div className="flex space-x-1 bg-slate-800/50 p-1 rounded-lg w-fit">
          {[
            { id: 'scan', label: 'New Scan', icon: Play },
            { id: 'monitor', label: 'Monitor', icon: Activity },
            { id: 'reports', label: 'Executive Reports', icon: FileText },
            { id: 'history', label: 'History', icon: Clock },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-all ${
                activeTab === tab.id 
                  ? 'bg-cyan-500 text-white shadow-lg' 
                  : 'text-slate-300 hover:text-white hover:bg-slate-700'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        {/* New Scan Tab */}
        {activeTab === 'scan' && (
          <div className="mt-6 space-y-6">
            {/* Target Input */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
                <Target className="w-5 h-5 mr-2 text-cyan-400" />
                Target Configuration
              </h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Target Domain or IP
                  </label>
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="example.com or 192.168.1.1"
                    className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  />
                </div>
                <div className="flex space-x-4">
                  <button
                    onClick={selectAllModules}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                  >
                    Select All
                  </button>
                  <button
                    onClick={clearSelection}
                    className="px-4 py-2 bg-slate-600 hover:bg-slate-700 text-white rounded-lg transition-colors"
                  >
                    Clear Selection
                  </button>
                  <span className="flex items-center text-slate-400">
                    {selectedModules.length} modules selected
                  </span>
                </div>
              </div>
            </div>

            {/* Module Selection */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
                <Settings className="w-5 h-5 mr-2 text-cyan-400" />
                Available Modules ({modules.length})
              </h2>
              
              <div className="space-y-6">
                {Object.entries(modulesByCategory).map(([category, categoryModules]) => (
                  <div key={category}>
                    <h3 className="text-lg font-medium text-slate-200 mb-3 flex items-center">
                      {getCategoryIcon(category)}
                      <span className="ml-2">{category}</span>
                      <span className="ml-2 text-sm text-slate-400">({categoryModules.length})</span>
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {categoryModules.map((module) => (
                        <div
                          key={module.script}
                          onClick={() => toggleModule(module.script)}
                          className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                            selectedModules.includes(module.script)
                              ? 'bg-cyan-500/20 border-cyan-500 ring-2 ring-cyan-500/30'
                              : 'bg-slate-700/50 border-slate-600 hover:border-slate-500 hover:bg-slate-700/70'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex-1">
                              <h4 className="text-white font-medium">{module.name}</h4>
                              <p className="text-sm text-slate-400 mt-1">{module.description}</p>
                            </div>
                            <div className="ml-3">
                              <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${
                                selectedModules.includes(module.script)
                                  ? 'bg-cyan-500 border-cyan-500'
                                  : 'border-slate-500'
                              }`}>
                                {selectedModules.includes(module.script) && (
                                  <CheckCircle className="w-3 h-3 text-white" />
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Start Scan Button */}
            <div className="flex justify-center">
              <button
                onClick={startScan}
                disabled={loading || !target || selectedModules.length === 0}
                className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 disabled:from-slate-600 disabled:to-slate-700 text-white font-semibold rounded-lg transition-all disabled:cursor-not-allowed flex items-center space-x-2"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-5 h-5 animate-spin" />
                    <span>Starting Assessment...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-5 h-5" />
                    <span>Start Security Assessment</span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* Enhanced Monitor Tab */}
        {activeTab === 'monitor' && activeScan && (
          <div className="mt-6 space-y-6">
            {/* Enhanced Scan Header with Risk Assessment */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-4">
                  <div className="p-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg">
                    <Target className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h2 className="text-xl font-semibold text-white flex items-center">
                      {getStatusIcon(activeScan.status)}
                      <span className="ml-2">Scanning {activeScan.target}</span>
                    </h2>
                    <p className="text-slate-400 text-sm">Scan ID: {activeScan.scan_id}</p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-4">
                  <button
                    onClick={() => fetchScanDetails(activeScan.scan_id)}
                    className="p-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors"
                  >
                    <RefreshCw className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => downloadReport(activeScan)}
                    className="p-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Progress and Risk Overview */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-slate-400 text-sm">Progress</span>
                    <BarChart3 className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="text-2xl font-bold text-white">{Math.round(activeScan.progress || 0)}%</div>
                  <div className="text-xs text-slate-400">
                    {activeScan.completed_modules}/{activeScan.total_modules} modules
                  </div>
                </div>

                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-slate-400 text-sm">Risk Score</span>
                    <overallThreat.icon className={`w-4 h-4 ${overallThreat.color}`} />
                  </div>
                  <div className={`text-2xl font-bold ${getRiskColor(metrics.avgRiskScore)}`}>
                    {metrics.avgRiskScore.toFixed(1)}/10
                  </div>
                  <div className={`text-xs ${overallThreat.color}`}>
                    {overallThreat.level} Risk
                  </div>
                </div>

                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-slate-400 text-sm">Threats</span>
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                  </div>
                  <div className="text-2xl font-bold text-red-400">{metrics.totalThreats}</div>
                  <div className="text-xs text-slate-400">
                    {metrics.highRiskModules} high-risk
                  </div>
                </div>

                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-slate-400 text-sm">Completed</span>
                    <CheckCircle className="w-4 h-4 text-green-400" />
                  </div>
                  <div className="text-2xl font-bold text-green-400">{metrics.completedModules}</div>
                  <div className="text-xs text-slate-400">
                    modules finished
                  </div>
                </div>
              </div>

              {/* Enhanced Progress Bar */}
              <div className="space-y-2">
                <div className="w-full bg-slate-700 rounded-full h-3 overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-600 transition-all duration-500 ease-out"
                    style={{ width: `${activeScan.progress || 0}%` }}
                  />
                </div>
                <div className="flex justify-between text-xs text-slate-400">
                  <span>Started {new Date(activeScan.created_at).toLocaleTimeString()}</span>
                  <span>ETA: ~{Math.round((100 - (activeScan.progress || 0)) / 10)} min</span>
                </div>
              </div>
            </div>

            {/* Filters and Search */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-4 border border-slate-700">
              <div className="flex flex-wrap items-center gap-4">
                <div className="flex items-center space-x-2">
                  <Filter className="w-4 h-4 text-slate-400" />
                  <span className="text-sm text-slate-300">Filter:</span>
                </div>
                
                <select 
                  value={filterCategory}
                  onChange={(e) => setFilterCategory(e.target.value)}
                  className="bg-slate-700 text-white text-sm rounded-lg px-3 py-1 border border-slate-600"
                >
                  <option value="all">All Categories</option>
                  <option value="Network & Infrastructure">Network & Infrastructure</option>
                  <option value="Security & Threat Intelligence">Security & Threat Intelligence</option>
                  <option value="Web Application Analysis">Web Application Analysis</option>
                </select>

                <select 
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                  className="bg-slate-700 text-white text-sm rounded-lg px-3 py-1 border border-slate-600"
                >
                  <option value="all">All Status</option>
                  <option value="completed">Completed</option>
                  <option value="running">Running</option>
                  <option value="queued">Queued</option>
                  <option value="failed">Failed</option>
                </select>

                <div className="flex-1 max-w-md">
                  <div className="relative">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Search modules or results..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full bg-slate-700 text-white text-sm rounded-lg pl-10 pr-4 py-2 border border-slate-600 focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Enhanced Module Results */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl border border-slate-700">
              <div className="p-6 border-b border-slate-700">
                <h3 className="text-lg font-semibold text-white flex items-center">
                  <Activity className="w-5 h-5 mr-2 text-cyan-400" />
                  Module Results ({filteredResults.length})
                </h3>
              </div>
              
              <div className="divide-y divide-slate-700">
                {filteredResults.map((result, index) => {
                  const isExpanded = expandedModules.has(index);
                  const riskScore = result.risk_score || calculateRiskScore(result);
                  const threat = getThreatLevel(riskScore);
                  const findings = result.findings || [];
                  const threatsDetected = result.threats_detected || 0;
                  
                  return (
                    <div key={index} className="p-4 hover:bg-slate-700/30 transition-colors">
                      <div 
                        className="flex items-center justify-between cursor-pointer"
                        onClick={() => toggleModuleExpansion(index)}
                      >
                        <div className="flex items-center space-x-4 flex-1">
                          <div className="flex items-center space-x-2">
                            {isExpanded ? 
                              <ChevronDown className="w-4 h-4 text-slate-400" /> : 
                              <ChevronRight className="w-4 h-4 text-slate-400" />
                            }
                            {getCategoryIcon(result.category)}
                          </div>
                          
                          <div className="flex-1">
                            <div className="flex items-center space-x-3">
                              <h4 className="text-white font-medium">{result.module_name}</h4>
                              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRiskBgColor(riskScore)} border`}>
                                Risk: {riskScore}/10
                              </span>
                              {threatsDetected > 0 && (
                                <span className="px-2 py-1 bg-red-500/20 border border-red-500/30 rounded-full text-xs font-medium text-red-400">
                                  {threatsDetected} threats
                                </span>
                              )}
                            </div>
                            <div className="flex items-center space-x-4 mt-1 text-sm text-slate-400">
                              <span className="capitalize">{result.category || 'Other'}</span>
                              <span>•</span>
                              <span>{result.execution_time}s</span>
                              {findings.length > 0 && (
                                <>
                                  <span>•</span>
                                  <span>{findings.length} findings</span>
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-3">
                          <threat.icon className={`w-5 h-5 ${threat.color}`} />
                          {getStatusIcon(result.status)}
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="mt-4 ml-6 space-y-4">
                          {/* Findings */}
                          {findings.length > 0 && (
                            <div className="bg-slate-700/30 rounded-lg p-4">
                              <h5 className="text-sm font-medium text-slate-300 mb-2 flex items-center">
                                <Eye className="w-4 h-4 mr-2" />
                                Key Findings
                              </h5>
                              <ul className="space-y-1">
                                {findings.map((finding, idx) => (
                                  <li key={idx} className="text-sm text-slate-400 flex items-start">
                                    <span className="w-1 h-1 bg-cyan-400 rounded-full mt-2 mr-2 flex-shrink-0" />
                                    {finding}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* Output */}
                          <div className="bg-slate-900/50 rounded-lg p-4">
                            <h5 className="text-sm font-medium text-slate-300 mb-2">Output</h5>
                            <pre className="text-sm text-slate-400 whitespace-pre-wrap font-mono">
                              {result.output || 'No output available'}
                            </pre>
                          </div>

                          {/* Actions */}
                          <div className="flex items-center space-x-2">
                            <button 
                              onClick={(e) => {
                                e.stopPropagation();
                                // Add view details functionality
                              }}
                              className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm rounded-lg transition-colors"
                            >
                              View Details
                            </button>
                            <button 
                              onClick={(e) => {
                                e.stopPropagation();
                                // Add export functionality
                              }}
                              className="px-3 py-1 bg-cyan-600 hover:bg-cyan-700 text-white text-sm rounded-lg transition-colors"
                            >
                              Export Data
                            </button>
                            {threatsDetected > 0 && (
                              <button 
                                onClick={(e) => {
                                  e.stopPropagation();
                                  // Add threat analysis functionality
                                }}
                                className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm rounded-lg transition-colors"
                              >
                                View Threats
                              </button>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {filteredResults.length === 0 && (
                <div className="p-8 text-center text-slate-400">
                  <Database className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No results match your current filters.</p>
                </div>
              )}
            </div>

            {/* Threat Summary (only show if threats detected) */}
            {metrics.totalThreats > 0 && (
              <div className="bg-red-500/10 border border-red-500/30 backdrop-blur-sm rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-red-400 flex items-center">
                    <AlertTriangle className="w-5 h-5 mr-2" />
                    Security Threats Detected
                  </h3>
                  <span className="px-3 py-1 bg-red-500/20 border border-red-500/30 rounded-full text-sm font-medium text-red-400">
                    {metrics.totalThreats} total threats
                  </span>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {activeScan.module_results
                    .filter(result => (result.threats_detected || 0) > 0)
                    .map((result, index) => {
                      const riskScore = result.risk_score || calculateRiskScore(result);
                      return (
                        <div key={index} className="bg-slate-800/50 rounded-lg p-4">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-white font-medium">{result.module_name}</span>
                            <span className="text-red-400 font-bold">{result.threats_detected || 0} threats</span>
                          </div>
                          <div className="text-sm text-slate-400">
                            Risk Score: <span className={getRiskColor(riskScore)}>{riskScore}/10</span>
                          </div>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Executive Reports Tab */}
        {activeTab === 'reports' && (
          <div className="mt-6 space-y-6">
            {/* Reports Header */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-semibold text-white flex items-center">
                    <FileText className="w-5 h-5 mr-2 text-cyan-400" />
                    Executive Security Reports
                  </h2>
                  <p className="text-slate-400 text-sm mt-1">
                    Business-ready security assessments and recommendations
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-slate-400">{completedScans.length} completed assessments</span>
                </div>
              </div>
            </div>

            {/* Scan Selection */}
            {completedScans.length > 0 ? (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Scan List */}
                <div className="lg:col-span-1 bg-slate-800/50 backdrop-blur-sm rounded-xl border border-slate-700">
                  <div className="p-4 border-b border-slate-700">
                    <h3 className="text-lg font-semibold text-white">Select Assessment</h3>
                  </div>
                  <div className="p-4 space-y-3 max-h-96 overflow-y-auto">
                    {completedScans.map(scan => {
                      const reportData = generateExecutiveReport(scan);
                      return (
                        <div
                          key={scan.scan_id}
                          onClick={() => setSelectedReportScan(scan)}
                          className={`p-4 rounded-lg cursor-pointer transition-all border-2 ${
                            selectedReportScan?.scan_id === scan.scan_id
                              ? 'bg-cyan-500/20 border-cyan-500'
                              : 'bg-slate-700/50 border-slate-600 hover:border-slate-500'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-white font-medium">{scan.target}</span>
                            <span className={`px-2 py-1 rounded-full text-xs ${reportData.businessImpact.bgColor} border`}>
                              {reportData.businessImpact.level}
                            </span>
                          </div>
                          <div className="text-sm text-slate-400">
                            {new Date(scan.created_at).toLocaleDateString()}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Executive Report Display */}
                <div className="lg:col-span-2">
                  {selectedReportScan ? (
                    (() => {
                      const reportData = generateExecutiveReport(selectedReportScan);
                      return (
                        <div className="space-y-6">
                          {/* Executive Summary */}
                          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                            <div className="flex items-center justify-between mb-6">
                              <h3 className="text-xl font-semibold text-white">Executive Summary</h3>
                              <div className="flex items-center space-x-2">
                                <button
                                  onClick={() => downloadExecutiveReport(reportData)}
                                  className="p-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                                  title="Download Report"
                                >
                                  <Download className="w-4 h-4" />
                                </button>
                                <button
                                  className="p-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors"
                                  title="Share Report"
                                >
                                  <Share2 className="w-4 h-4" />
                                </button>
                                <button
                                  className="p-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors"
                                  title="Print Report"
                                >
                                  <Printer className="w-4 h-4" />
                                </button>
                              </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                              {/* Overall Risk Score */}
                              <div className="bg-slate-700/50 rounded-lg p-4">
                                <div className="flex items-center justify-between mb-2">
                                  <span className="text-slate-400 text-sm">Risk Score</span>
                                  <Shield className="w-4 h-4 text-cyan-400" />
                                </div>
                                <div className={`text-2xl font-bold ${getRiskColor(reportData.metrics.avgRiskScore)}`}>
                                  {reportData.metrics.avgRiskScore.toFixed(1)}/10
                                </div>
                                <div className="text-xs text-slate-400">
                                  {getThreatLevel(reportData.metrics.avgRiskScore).level} Risk
                                </div>
                              </div>

                              {/* Compliance Score */}
                              <div className="bg-slate-700/50 rounded-lg p-4">
                                <div className="flex items-center justify-between mb-2">
                                  <span className="text-slate-400 text-sm">Compliance</span>
                                  <Award className="w-4 h-4 text-green-400" />
                                </div>
                                <div className="text-2xl font-bold text-green-400">
                                  {reportData.complianceScore}%
                                </div>
                                <div className="text-xs text-slate-400">
                                  Security Standards
                                </div>
                              </div>

                              {/* Business Impact */}
                              <div className="bg-slate-700/50 rounded-lg p-4">
                                <div className="flex items-center justify-between mb-2">
                                  <span className="text-slate-400 text-sm">Business Impact</span>
                                  <Building className="w-4 h-4 text-yellow-400" />
                                </div>
                                <div className={`text-lg font-bold ${reportData.businessImpact.color}`}>
                                  {reportData.businessImpact.level}
                                </div>
                                <div className="text-xs text-slate-400">
                                  Risk Level
                                </div>
                              </div>
                            </div>

                            {/* Key Metrics */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                              <div className="text-center">
                                <div className="text-2xl font-bold text-red-400">{reportData.metrics.totalThreats}</div>
                                <div className="text-xs text-slate-400">Threats Found</div>
                              </div>
                              <div className="text-center">
                                <div className="text-2xl font-bold text-yellow-400">{reportData.metrics.highRiskModules}</div>
                                <div className="text-xs text-slate-400">High Risk Areas</div>
                              </div>
                              <div className="text-center">
                                <div className="text-2xl font-bold text-green-400">{reportData.metrics.completedModules}</div>
                                <div className="text-xs text-slate-400">Areas Assessed</div>
                              </div>
                              <div className="text-center">
                                <div className="text-2xl font-bold text-cyan-400">{reportData.recommendations.length}</div>
                                <div className="text-xs text-slate-400">Recommendations</div>
                              </div>
                            </div>
                          </div>

                          {/* Business Impact Analysis */}
                          <div className={`${reportData.businessImpact.bgColor} border backdrop-blur-sm rounded-xl p-6`}>
                            <h4 className="text-lg font-semibold text-white mb-3 flex items-center">
                              <AlertOctagon className="w-5 h-5 mr-2" />
                              Business Impact Analysis
                            </h4>
                            <p className={`${reportData.businessImpact.color} text-sm`}>
                              {reportData.businessImpact.description}
                            </p>
                          </div>

                          {/* Key Recommendations */}
                          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl border border-slate-700">
                            <div className="p-6 border-b border-slate-700">
                              <h4 className="text-lg font-semibold text-white flex items-center">
                                <CheckCircle2 className="w-5 h-5 mr-2 text-green-400" />
                                Priority Recommendations
                              </h4>
                            </div>
                            <div className="p-6 space-y-4">
                              {reportData.recommendations.map((rec, index) => (
                                <div key={index} className="flex items-start space-x-4 p-4 bg-slate-700/30 rounded-lg">
                                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                                    rec.priority === 'Critical' ? 'bg-red-500/20 text-red-400' :
                                    rec.priority === 'High' ? 'bg-yellow-500/20 text-yellow-400' :
                                    'bg-green-500/20 text-green-400'
                                  }`}>
                                    {index + 1}
                                  </div>
                                  <div className="flex-1">
                                    <div className="flex items-center justify-between mb-2">
                                      <h5 className="text-white font-medium">{rec.title}</h5>
                                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                                        rec.priority === 'Critical' ? 'bg-red-500/20 text-red-400' :
                                        rec.priority === 'High' ? 'bg-yellow-500/20 text-yellow-400' :
                                        'bg-green-500/20 text-green-400'
                                      }`}>
                                        {rec.priority}
                                      </span>
                                    </div>
                                    <p className="text-slate-400 text-sm mb-2">{rec.description}</p>
                                    <div className="flex items-center space-x-4 text-xs text-slate-500">
                                      <span>Effort: {rec.effort}</span>
                                      <span>•</span>
                                      <span>Impact: {rec.impact}</span>
                                    </div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Next Steps */}
                          <div className="bg-gradient-to-r from-cyan-500/10 to-blue-600/10 border border-cyan-500/30 rounded-xl p-6">
                            <h4 className="text-lg font-semibold text-white mb-4 flex items-center">
                              <ArrowRight className="w-5 h-5 mr-2 text-cyan-400" />
                              Recommended Next Steps
                            </h4>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                              <div className="text-center p-4 bg-slate-800/50 rounded-lg">
                                <Clock3 className="w-8 h-8 text-yellow-400 mx-auto mb-2" />
                                <div className="text-white font-medium">Immediate (0-30 days)</div>
                                <div className="text-sm text-slate-400">Address critical vulnerabilities</div>
                              </div>
                              <div className="text-center p-4 bg-slate-800/50 rounded-lg">
                                <TrendingUp className="w-8 h-8 text-blue-400 mx-auto mb-2" />
                                <div className="text-white font-medium">Short-term (30-90 days)</div>
                                <div className="text-sm text-slate-400">Implement security controls</div>
                              </div>
                              <div className="text-center p-4 bg-slate-800/50 rounded-lg">
                                <RefreshCw className="w-8 h-8 text-green-400 mx-auto mb-2" />
                                <div className="text-white font-medium">Ongoing</div>
                                <div className="text-sm text-slate-400">Regular assessments</div>
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })()
                  ) : (
                    <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-8 border border-slate-700 text-center">
                      <FileText className="w-16 h-16 text-slate-600 mx-auto mb-4" />
                      <h3 className="text-lg font-semibold text-slate-400 mb-2">Select an Assessment</h3>
                      <p className="text-slate-500">Choose a completed scan from the list to view its executive report.</p>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-8 border border-slate-700 text-center">
                <FileText className="w-16 h-16 text-slate-600 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-slate-400 mb-2">No Completed Assessments</h3>
                <p className="text-slate-500 mb-4">Complete a security scan to generate executive reports.</p>
                <button
                  onClick={() => setActiveTab('scan')}
                  className="px-6 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                >
                  Start New Assessment
                </button>
              </div>
            )}
          </div>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div className="mt-6 bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-white flex items-center">
                <Calendar className="w-5 h-5 mr-2 text-cyan-400" />
                Assessment History
              </h2>
              <button
                onClick={fetchScans}
                className="p-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>
            
            <div className="space-y-3">
              {scans.map(scan => (
                <div key={scan.scan_id} className="flex items-center justify-between p-4 bg-slate-700/50 rounded-lg">
                  <div className="flex items-center space-x-4">
                    {getStatusIcon(scan.status)}
                    <div>
                      <div className="text-white font-medium">{scan.target}</div>
                      <div className="text-sm text-slate-400">
                        {new Date(scan.created_at).toLocaleString()} • {scan.total_modules} modules
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {scan.status === 'completed' && (
                      <>
                        <button
                          onClick={() => {
                            setSelectedReportScan(scan);
                            setActiveTab('reports');
                          }}
                          className="p-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                          title="View Executive Report"
                        >
                          <FileText className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => downloadReport(scan)}
                          className="p-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                          title="Download Technical Report"
                        >
                          <Download className="w-4 h-4" />
                        </button>
                      </>
                    )}
                    {(scan.status === 'running' || scan.status === 'queued') && (
                      <button
                        onClick={() => {
                          setActiveScan(scan);
                          setActiveTab('monitor');
                          fetchScanDetails(scan.scan_id);
                        }}
                        className="p-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"
                        title="Monitor Progress"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
              
              {scans.length === 0 && (
                <div className="text-center py-8 text-slate-400">
                  No assessments found. Start your first security scan to see results here.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;