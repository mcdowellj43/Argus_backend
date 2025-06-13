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
  Server
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
                <p className="text-sm text-slate-400">Reconnaissance Dashboard</p>
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
            { id: 'history', label: 'History', icon: Clock },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-all ${
                activeTab === tab.id 
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-lg' 
                  : 'text-slate-400 hover:text-white hover:bg-slate-700'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 pb-8">
        {/* New Scan Tab */}
        {activeTab === 'scan' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Target Input */}
            <div className="lg:col-span-3">
              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
                  <Search className="w-5 h-5 mr-2 text-cyan-400" />
                  Target Configuration
                </h2>
                <div className="flex space-x-4">
                  <div className="flex-1">
                    <input
                      type="text"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      placeholder="Enter domain or IP address (e.g., example.com, 192.168.1.1)"
                      className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                    />
                  </div>
                  <div className="flex space-x-2">
                    <button
                      onClick={selectAllModules}
                      className="px-4 py-3 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors"
                    >
                      Select All
                    </button>
                    <button
                      onClick={clearSelection}
                      className="px-4 py-3 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors"
                    >
                      Clear
                    </button>
                    <button
                      onClick={startScan}
                      disabled={loading || !target || selectedModules.length === 0}
                      className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 text-white rounded-lg transition-all flex items-center space-x-2 disabled:cursor-not-allowed"
                    >
                      {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                      <span>{loading ? 'Starting...' : 'Start Scan'}</span>
                    </button>
                  </div>
                </div>
                <div className="mt-3 text-sm text-slate-400">
                  Selected: {selectedModules.length} of {modules.length} modules
                </div>
              </div>
            </div>

            {/* Module Selection */}
            <div className="lg:col-span-3">
              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
                <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
                  <Settings className="w-5 h-5 mr-2 text-cyan-400" />
                  Module Selection
                </h2>
                <div className="space-y-6">
                  {Object.entries(modulesByCategory).map(([category, categoryModules]) => (
                    <div key={category}>
                      <h3 className="text-lg font-medium text-white mb-3 flex items-center">
                        {getCategoryIcon(category)}
                        <span className="ml-2">{category}</span>
                        <span className="ml-2 text-sm text-slate-400">({categoryModules.length} modules)</span>
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {categoryModules.map(module => (
                          <div
                            key={module.script}
                            onClick={() => toggleModule(module.script)}
                            className={`p-4 rounded-lg border cursor-pointer transition-all ${
                              selectedModules.includes(module.script)
                                ? 'bg-cyan-500/10 border-cyan-500 ring-1 ring-cyan-500'
                                : 'bg-slate-700/50 border-slate-600 hover:border-slate-500'
                            }`}
                          >
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <h4 className="text-white font-medium text-sm">{module.name}</h4>
                                <p className="text-slate-400 text-xs mt-1 line-clamp-2">{module.description}</p>
                                <div className="flex items-center mt-2 text-xs text-slate-500">
                                  <Clock className="w-3 h-3 mr-1" />
                                  <span>~{module.estimated_time}s</span>
                                  {module.requires_api_key && (
                                    <>
                                      <span className="mx-1">•</span>
                                      <span className="text-yellow-400">API Key Required</span>
                                    </>
                                  )}
                                </div>
                              </div>
                              <div className={`w-4 h-4 rounded border-2 flex items-center justify-center ${
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
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Monitor Tab */}
        {activeTab === 'monitor' && activeScan && (
          <div className="space-y-6">
            {/* Scan Header */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-xl font-semibold text-white flex items-center">
                    {getStatusIcon(activeScan.status)}
                    <span className="ml-2">Scanning {activeScan.target}</span>
                  </h2>
                  <p className="text-slate-400 text-sm">Scan ID: {activeScan.scan_id}</p>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-white">{Math.round(activeScan.progress || 0)}%</div>
                  <div className="text-sm text-slate-400">
                    {activeScan.completed_modules}/{activeScan.total_modules} modules
                  </div>
                </div>
              </div>
              
              {/* Progress Bar */}
              <div className="w-full bg-slate-700 rounded-full h-2 mb-4">
                <div 
                  className="bg-gradient-to-r from-cyan-500 to-blue-600 h-2 rounded-full transition-all duration-500"
                  style={{ width: `${activeScan.progress || 0}%` }}
                />
              </div>

              {activeScan.current_module && (
                <div className="text-sm text-slate-300">
                  Currently running: <span className="text-cyan-400">{activeScan.current_module}</span>
                </div>
              )}
            </div>

            {/* Module Results */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold text-white mb-4">Module Results</h3>
              <div className="space-y-3">
                {activeScan.module_results?.map((result, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-slate-700/50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      {getStatusIcon(result.status)}
                      <span className="text-white">{result.module_name}</span>
                    </div>
                    <div className="flex items-center space-x-4 text-sm text-slate-400">
                      <span>{result.execution_time}s</span>
                      {result.output && (
                        <button
                          onClick={() => {
                            const modal = document.createElement('div');
                            modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4';
                            modal.innerHTML = `
                              <div class="bg-slate-800 rounded-xl p-6 max-w-4xl max-h-96 overflow-auto">
                                <h4 class="text-white font-semibold mb-3">${result.module_name} Output</h4>
                                <pre class="text-slate-300 text-sm whitespace-pre-wrap">${result.output}</pre>
                                <button class="mt-4 px-4 py-2 bg-slate-700 text-white rounded-lg" onclick="this.parentElement.parentElement.remove()">Close</button>
                              </div>
                            `;
                            document.body.appendChild(modal);
                          }}
                          className="text-cyan-400 hover:text-cyan-300"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-white flex items-center">
                <Calendar className="w-5 h-5 mr-2 text-cyan-400" />
                Scan History
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
                      <button
                        onClick={() => downloadReport(scan)}
                        className="p-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                    )}
                    {(scan.status === 'running' || scan.status === 'queued') && (
                      <button
                        onClick={() => {
                          setActiveScan(scan);
                          setActiveTab('monitor');
                          fetchScanDetails(scan.scan_id);
                        }}
                        className="p-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
              
              {scans.length === 0 && (
                <div className="text-center py-8 text-slate-400">
                  No scans found. Start your first scan to see results here.
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