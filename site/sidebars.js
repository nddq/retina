/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */

// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  // By default, Docusaurus generates a sidebar from the docs folder structure
  //tutorialSidebar: [{type: 'autogenerated', dirName: '.'}],

  // But you can create a sidebar manually

  tutorialSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Quick Installation',
      items: [
        'installation/setup',
        'installation/prometheus-unmanaged',
        'installation/grafana',
        'installation/cli',
        'installation/config',
      ],
    },
    {
      type: 'category',
      label: 'Metrics',
      items: [
        'metrics/modes',
        'metrics/basic',
        'metrics/advanced',
        'metrics/configuration',
        'metrics/annotations',
        {
          type: 'category',
          label: 'Plugins',
          items: [
            'metrics/plugins/packetforward',
            'metrics/plugins/dropreason',
            'metrics/plugins/linuxutil',
            'metrics/plugins/dns',
            'metrics/plugins/hnsstats',
            'metrics/plugins/packetparser',
            'metrics/plugins/tcpretrans',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Captures',
      items: [
        'captures/readme',
        'captures/cli',
      ],
    },
    {
      type: 'category',
      label: 'CRDs',
      items: [
        'CRDs/Capture',
        'CRDs/RetinaEndpoint',
        'CRDs/MetricsConfiguration',
      ],
    },
    {
      type: 'category',
      label: 'Troubleshooting Guides',
      items: [
        'troubleshooting/capture',
        'troubleshooting/basic-metrics',
      ],
    },
    'contributing/readme',
  ],

};

module.exports = sidebars;
