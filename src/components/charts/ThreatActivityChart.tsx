import React, { useState } from 'react';

interface ActivityPoint {
  time: string;
  totalInspected: number;
  elevatedThreats: number;
  avgScore: number;
}

interface ThreatActivityChartProps {
  data: ActivityPoint[];
}

export const ThreatActivityChart: React.FC<ThreatActivityChartProps> = ({ data }) => {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  if (!data || data.length === 0) {
    return <div style={{ color: '#64748b', padding: '2rem', textAlign: 'center' }}>No telemetry data available</div>;
  }

  // Dimensions
  const width = 640;
  const height = 180;
  const paddingX = 40;
  const paddingY = 25;

  const maxThreats = Math.max(...data.map(d => d.elevatedThreats), 8);
  const maxScore = 100;

  // Compute SVG Points
  const getX = (index: number) => {
    if (data.length <= 1) return width / 2;
    return paddingX + (index / (data.length - 1)) * (width - 2 * paddingX);
  };

  const getYScore = (score: number) => {
    return height - paddingY - (score / maxScore) * (height - 2 * paddingY);
  };

  // Build path strings
  const scorePoints = data.map((d, i) => `${getX(i)},${getYScore(d.avgScore)}`);
  const scorePath = data.length === 1
    ? `M ${getX(0) - 20},${getYScore(data[0].avgScore)} L ${getX(0) + 20},${getYScore(data[0].avgScore)}`
    : `M ${scorePoints.join(' L ')}`;
  const scoreAreaPath = data.length === 1
    ? `M ${getX(0) - 20},${getYScore(data[0].avgScore)} L ${getX(0) + 20},${getYScore(data[0].avgScore)} L ${getX(0) + 20},${height - paddingY} L ${getX(0) - 20},${height - paddingY} Z`
    : `${scorePath} L ${getX(data.length - 1)},${height - paddingY} L ${getX(0)},${height - paddingY} Z`;

  return (
    <div style={{ width: '100%', position: 'relative' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', fontSize: '0.78rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '2px', background: '#00e5ff' }} />
            <span style={{ color: '#cbd5e1' }}>Average Threat Score</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '2px', background: 'rgba(239, 68, 68, 0.7)' }} />
            <span style={{ color: '#cbd5e1' }}>Elevated Alerts</span>
          </div>
        </div>
        <span style={{ color: '#64748b', fontSize: '0.72rem' }}>Timeline (UTC Hours)</span>
      </div>

      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: '100%', height: 'auto', overflow: 'visible' }}
      >
        <defs>
          <linearGradient id="scoreAreaGradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#00e5ff" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#00e5ff" stopOpacity="0.0" />
          </linearGradient>
          <linearGradient id="scoreLineGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#0284c7" />
            <stop offset="50%" stopColor="#00e5ff" />
            <stop offset="100%" stopColor="#f43f5e" />
          </linearGradient>
        </defs>

        {/* Horizontal grid lines */}
        {[0, 25, 50, 75, 100].map((score) => {
          const y = getYScore(score);
          return (
            <g key={score}>
              <line
                x1={paddingX}
                y1={y}
                x2={width - paddingX}
                y2={y}
                stroke="rgba(255, 255, 255, 0.06)"
                strokeDasharray="3 3"
              />
              <text
                x={paddingX - 8}
                y={y + 3}
                fill="#64748b"
                fontSize="9"
                textAnchor="end"
                fontFamily="var(--font-mono)"
              >
                {score}
              </text>
            </g>
          );
        })}

        {/* Shaded Area */}
        <path d={scoreAreaPath} fill="url(#scoreAreaGradient)" />

        {/* Threat Score Line */}
        <path
          d={scorePath}
          fill="none"
          stroke="url(#scoreLineGradient)"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        {/* Data points & Bars for elevated threats */}
        {data.map((d, i) => {
          const x = getX(i);
          const y = getYScore(d.avgScore);
          const barHeight = (d.elevatedThreats / maxThreats) * 60;
          const isHovered = hoveredIndex === i;

          return (
            <g key={d.time} onMouseEnter={() => setHoveredIndex(i)} onMouseLeave={() => setHoveredIndex(null)} style={{ cursor: 'pointer' }}>
              {/* Elevated alert count bar */}
              {d.elevatedThreats > 0 && (
                <rect
                  x={x - 6}
                  y={height - paddingY - barHeight}
                  width="12"
                  height={barHeight}
                  fill={d.elevatedThreats >= 4 ? 'rgba(239, 68, 68, 0.45)' : 'rgba(249, 115, 22, 0.35)'}
                  rx="2"
                  stroke={d.elevatedThreats >= 4 ? '#ef4444' : '#f97316'}
                  strokeWidth="1"
                />
              )}

              {/* Score dot */}
              <circle
                cx={x}
                cy={y}
                r={isHovered ? 5.5 : 3.5}
                fill={isHovered ? '#00e5ff' : '#070b14'}
                stroke="#00e5ff"
                strokeWidth="2"
              />

              {/* Time label */}
              <text
                x={x}
                y={height - 6}
                fill={isHovered ? '#00e5ff' : '#64748b'}
                fontSize="10"
                textAnchor="middle"
                fontWeight={isHovered ? '700' : '500'}
                fontFamily="var(--font-mono)"
              >
                {d.time}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Floating tooltip */}
      {hoveredIndex !== null && (
        <div
          style={{
            position: 'absolute',
            top: '0',
            left: `${(hoveredIndex / (data.length - 1)) * 75 + 10}%`,
            transform: 'translateX(-50%)',
            background: 'rgba(9, 15, 26, 0.95)',
            border: '1px solid var(--pt-border-cyan)',
            padding: '0.5rem 0.75rem',
            borderRadius: '6px',
            fontSize: '0.75rem',
            color: '#ffffff',
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.6)',
            pointerEvents: 'none',
            zIndex: 10,
            whiteSpace: 'nowrap'
          }}
        >
          <div style={{ color: '#00e5ff', fontWeight: 700, marginBottom: '0.2rem' }}>
            {data[hoveredIndex].time} UTC Telemetry
          </div>
          <div>Avg Risk Score: <strong style={{ color: '#f8fafc' }}>{data[hoveredIndex].avgScore}</strong>/100</div>
          <div>Elevated Alerts: <strong style={{ color: '#f87171' }}>{data[hoveredIndex].elevatedThreats}</strong></div>
          <div style={{ color: '#94a3b8', fontSize: '0.7rem' }}>Processes Checked: {data[hoveredIndex].totalInspected}</div>
        </div>
      )}
    </div>
  );
};
