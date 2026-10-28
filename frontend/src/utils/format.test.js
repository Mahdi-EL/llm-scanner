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
  // pydantic's generic messages get the field's name; the validators' own sentences are kept as they are
  const v = (loc, msg) => errorMessage({ response: { data: { detail: [{ loc, msg }] } } });
  expect(v(['body', 'api_url'], 'String should have at most 2048 characters')).toBe('API URL: string should have at most 2048 characters');
  expect(v(['body', 'name'], 'String should have at least 1 character')).toBe('Name: string should have at least 1 character');
  expect(v(['body', 'alert_drop'], 'Input should be greater than or equal to 1')).toBe('Alert threshold: input should be greater than or equal to 1');
  expect(v(['body', 'email'], 'value is not a valid email address: An email address must have an @-sign.'))
    .toBe('Email: value is not a valid email address: An email address must have an @-sign.');
  expect(v(['body', 'username'], 'Value error, Usernames are 3 to 32 characters')).toBe('Usernames are 3 to 32 characters');
  expect(v(['body'], 'Input should be a valid dictionary')).toBe('Input should be a valid dictionary');
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
