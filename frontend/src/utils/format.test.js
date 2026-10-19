import { toCSV, gradeOf, scoreColor, isActive, formatDuration, shortDate, fmtNum, safeNext } from './format';
import { errorMessage } from '../services/api';

test('CSV cells are quoted and formulas are neutralized', () => {
  const csv = toCSV([['Target', 'Score'], ['=HYPERLINK("http://evil")', 49], ['Bot, "prod"', null]]);
  const lines = csv.split('\r\n');
  expect(lines[0]).toBe('"Target","Score"');
  expect(lines[1]).toBe('"\'=HYPERLINK(""http://evil"")","49"');
  expect(lines[2]).toBe('"Bot, ""prod""",""');
  expect(toCSV([['+1', '-2', '@x']])).toBe('"\'+1","\'-2","\'@x"');
});

test('grades and colours follow the score bands', () => {
  expect([95, 85, 75, 55, 49].map(gradeOf)).toEqual(['A', 'B', 'C', 'D', 'F']);
  expect(scoreColor(90)).toBe('#16a34a');
  expect(scoreColor(60)).toBe('#b45309');
  expect(scoreColor(10)).toBe('#dc2626');
  expect(gradeOf(null)).toBeNull();
});

test('active scans and durations', () => {
  expect(isActive({ status: 'pending' })).toBe(true);
  expect(isActive({ status: 'complete' })).toBe(false);
  expect(formatDuration(125)).toBe('2m 05s');
  expect(formatDuration(9)).toBe('9s');
});

test('API error messages are readable', () => {
  expect(errorMessage({ response: { data: { detail: 'Monthly scan limit reached' } } })).toBe('Monthly scan limit reached');
  expect(errorMessage({ response: { data: { detail: [{ msg: 'Value error, Target name can\'t be empty' }] } } }))
    .toBe('Target name can\'t be empty');
  expect(errorMessage({ message: 'Network Error' })).toMatch(/reach the server/);
  expect(errorMessage({}, 'fallback')).toBe('fallback');
});

describe('shortDate / fmtNum', () => {
  it('formats in English whatever the browser locale', () => {
    expect(shortDate('2026-10-19T08:00:00Z')).toBe('Oct 19');
    expect(shortDate('2026-10-19T08:00:00Z', true)).toBe('Oct 19, 2026');
    expect(shortDate(null)).toBe('—');
    expect(fmtNum(1090)).toBe('1,090');
  });
});

test('safeNext only allows paths on this site', () => {
  expect(safeNext('/reports?x=1')).toBe('/reports?x=1');
  for (const bad of ['//evil.com', '/\\evil.com', 'https://evil.com', 'javascript:alert(1)', null, undefined, ''])
    expect(safeNext(bad)).toBe('/');
});
