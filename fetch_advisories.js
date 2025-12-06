const fs = require('fs');
const path = require('path');
const axios = require('axios');

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'advisories.json');
const API_URL = 'https://api.github.com/advisories?ecosystem=npm&type=malware';

async function fetchAdvisories() {
  try {
    console.log('Fetching advisories...');

    let allAdvisories = [];
    let page = 1;
    let hasNextPage = true;

    const response = await axios.get(API_URL, {
      headers: {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        // Add User-Agent to be a good citizen
        'User-Agent': 'pistachio-action-fetcher'
      }
    });

    const newAdvisories = response.data;
    console.log(`Fetched ${newAdvisories.length} advisories.`);

    // Ensure data directory exists
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    // Read existing data
    let existingAdvisories = [];
    if (fs.existsSync(DATA_FILE)) {
      const fileContent = fs.readFileSync(DATA_FILE, 'utf8');
      try {
        existingAdvisories = JSON.parse(fileContent);
      } catch (e) {
        console.error('Error parsing existing data file, starting fresh.');
      }
    }

    // Deduplicate
    const existingIds = new Set(existingAdvisories.map(a => a.ghsa_id));
    let addedCount = 0;

    for (const advisory of newAdvisories) {
      if (!existingIds.has(advisory.ghsa_id)) {
        existingAdvisories.push(advisory);
        existingIds.add(advisory.ghsa_id);
        addedCount++;
      }
    }

    console.log(`Added ${addedCount} new advisories.`);

    if (addedCount > 0) {
      // Save back to file
      fs.writeFileSync(DATA_FILE, JSON.stringify(existingAdvisories, null, 2));
      console.log('Saved updated advisories to file.');
    } else {
      console.log('No new advisories to save.');
    }

  } catch (error) {
    console.error('Error fetching advisories:', error.message);
    process.exit(1);
  }
}

fetchAdvisories();
