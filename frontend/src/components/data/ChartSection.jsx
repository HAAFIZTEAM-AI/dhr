import React from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement } from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement);

export default function ChartSection({ type, data, options }) {
  const charts = {
    doughnut: Doughnut,
    bar: Bar,
    line: Line,
  };
  const ChartComponent = charts[type] || Bar;
  return <ChartComponent data={data} options={options} />;
}